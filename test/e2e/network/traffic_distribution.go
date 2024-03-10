/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eservice "k8s.io/kubernetes/test/e2e/framework/service"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	"k8s.io/kubernetes/test/e2e/network/common"
	"k8s.io/kubernetes/test/utils/format"
	admissionapi "k8s.io/pod-security-admission/api"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/gcustom"
)

var _ = common.SIGDescribe("TrafficDistribution", func() {
	f := framework.NewDefaultFramework("traffic-distribution")
	f.NamespacePodSecurityLevel = admissionapi.LevelPrivileged

	var c clientset.Interface

	ginkgo.BeforeEach(func(ctx context.Context) {
		c = f.ClientSet
		e2eskipper.SkipUnlessMultizone(ctx, c)
	})

	////////////////////////////////////////////////////////////////////////////
	// Helper functions
	////////////////////////////////////////////////////////////////////////////

	// endpointSlicesForService returns a helper function to be used with
	// gomega.Eventually(...). It fetches the EndpointSlcies for the given
	// serviceName.
	endpointSlicesForService := func(serviceName string) any {
		return func(ctx context.Context) ([]discoveryv1.EndpointSlice, error) {
			slices, err := c.DiscoveryV1().EndpointSlices(f.Namespace.Name).List(ctx, metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", discoveryv1.LabelServiceName, serviceName)})
			if err != nil {
				return nil, err
			}
			return slices.Items, nil
		}
	}

	// endpointSlicesHaveSameZoneHints returns a matcher function to be used with
	// gomega.Eventually().Should(...). It checks that the passed EndpointSlices
	// have zone-hints which match the endpoint's zone.
	endpointSlicesHaveSameZoneHints := gcustom.MakeMatcher(func(slices []discoveryv1.EndpointSlice) (bool, error) {
		for _, slice := range slices {
			for _, endpoint := range slice.Endpoints {
				var ip string
				if len(endpoint.Addresses) > 0 {
					ip = endpoint.Addresses[0]
				}
				var zone string
				if endpoint.Zone != nil {
					zone = *endpoint.Zone
				}
				if endpoint.Hints == nil || len(endpoint.Hints.ForZones) != 1 || endpoint.Hints.ForZones[0].Name != zone {
					return false, fmt.Errorf("endpoint with ip %v does not have the correct hint, want hint for zone %q", ip, zone)
				}
			}
		}
		return true, nil
	})

	// requestsFromClient returns a helper function to be used with
	// gomega.Eventually(...). It fetches the logs from the clientPod and returns
	// them in reverse-chronological order.
	requestsFromClient := func(clientPod *corev1.Pod) any {
		return func(ctx context.Context) (reverseChronologicalLogLines []string, err error) {
			logs, err := e2epod.GetPodLogs(ctx, c, f.Namespace.Name, clientPod.Name, clientPod.Spec.Containers[0].Name)
			if err != nil {
				return nil, err
			}
			framework.Logf("Logs from client=%q:\n%v", clientPod.GetName(), logs)
			logLines := strings.Split(logs, "\n")
			slices.Reverse(logLines)
			return logLines, nil
		}
	}

	////////////////////////////////////////////////////////////////////////////
	// Main test specifications.
	////////////////////////////////////////////////////////////////////////////

	ginkgo.When("Service has trafficDistribution=PreferClose", func() {
		ginkgo.It("should route traffic to an endpoint that is close to the client", func(ctx context.Context) {

			ginkgo.By("finding 3 zones with schedulable nodes")
			allZonesSet, err := e2enode.GetSchedulableClusterZones(ctx, c)
			framework.ExpectNoError(err)
			if len(allZonesSet) < 3 {
				framework.Failf("got %d zones with schedulable nodes, want atleast 3 zones with schedulable nodes", len(allZonesSet))
			}
			zones := allZonesSet.UnsortedList()[:3]

			ginkgo.By(fmt.Sprintf("finding a node in each of the chosen 3 zones %v", zones))
			nodeList, err := e2enode.GetReadySchedulableNodes(ctx, c)
			framework.ExpectNoError(err)
			nodeForZone := make(map[string]string)
			for _, zone := range zones {
				found := false
				for _, node := range nodeList.Items {
					if zone == node.Labels[corev1.LabelTopologyZone] {
						found = true
						nodeForZone[zone] = node.GetName()
					}
				}
				if !found {
					framework.Failf("could not find a node in zone %q; nodes=\n%v", zone, format.Object(nodeList, 1 /* indent one level */))
				}
			}

			ginkgo.By(fmt.Sprintf("creating 1 pod each in 2 zones %v (out of the total 3 zones)", zones[:2]))
			zoneForServingPod := make(map[string]string)
			var servingPods []*corev1.Pod
			servingPodLabels := map[string]string{"app": f.UniqueName}
			for _, zone := range zones[:2] {
				pod := e2epod.NewAgnhostPod(f.Namespace.Name, "serving-pod-in-"+zone, nil, nil, nil, "serve-hostname")
				pod.Spec.NodeName = nodeForZone[zone]
				pod.Labels = servingPodLabels

				servingPods = append(servingPods, pod)
				zoneForServingPod[pod.Name] = zone
				ginkgo.DeferCleanup(framework.IgnoreNotFound(c.CoreV1().Pods(f.Namespace.Name).Delete), pod.GetName(), metav1.DeleteOptions{})
			}
			e2epod.NewPodClient(f).CreateBatch(ctx, servingPods)

			trafficDist := corev1.ServiceTrafficDistributionPreferClose
			svc := createServiceReportErr(ctx, c, f.Namespace.Name, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "traffic-dist-test-service",
				},
				Spec: corev1.ServiceSpec{
					Selector:            servingPodLabels,
					TrafficDistribution: &trafficDist,
					Ports: []corev1.ServicePort{{
						Port:       80,
						TargetPort: intstr.FromInt32(9376),
						Protocol:   corev1.ProtocolTCP,
					}},
				},
			})
			ginkgo.By(fmt.Sprintf("creating a service=%q with trafficDistribution=%v", svc.GetName(), *svc.Spec.TrafficDistribution))
			ginkgo.DeferCleanup(framework.IgnoreNotFound(c.CoreV1().Services(f.Namespace.Name).Delete), svc.GetName(), metav1.DeleteOptions{})

			ginkgo.By("ensuring EndpointSlice for service have correct same-zone hints")
			gomega.Eventually(ctx, endpointSlicesForService(svc.GetName())).WithPolling(5 * time.Second).WithTimeout(e2eservice.ServiceEndpointsTimeout).Should(endpointSlicesHaveSameZoneHints)

			ginkgo.By("keeping traffic within the same zone as the client, when serving pods exist in the same zone")

			createClientPod := func(ctx context.Context, zone string) *corev1.Pod {
				pod := e2epod.NewAgnhostPod(f.Namespace.Name, "client-pod-in-"+zone, nil, nil, nil)
				pod.Spec.NodeName = nodeForZone[zone]
				cmd := fmt.Sprintf(`date; for i in $(seq 1 3000); do sleep 1; echo "Date: $(date) Try: ${i}"; curl -q -s --connect-timeout 2 http://%s:80/ ; echo; done`, svc.Name)
				pod.Spec.Containers[0].Command = []string{"/bin/sh", "-c", cmd}
				pod.Spec.Containers[0].Name = pod.Name

				ginkgo.DeferCleanup(framework.IgnoreNotFound(c.CoreV1().Pods(f.Namespace.Name).Delete), pod.GetName(), metav1.DeleteOptions{})
				return e2epod.NewPodClient(f).CreateSync(ctx, pod)
			}

			for _, clientZone := range zones[:2] {
				framework.Logf("creating a client pod for probing the service from zone=%q which also has a serving pod", clientZone)
				clientPod := createClientPod(ctx, clientZone)

				framework.Logf("ensuring that requests from clientPod=%q on zone=%q stay in the same zone", clientPod.Name, clientZone)

				requestsSucceedAndStayInSameZone := gcustom.MakeMatcher(func(reverseChronologicalLogLines []string) (bool, error) {
					logLines := reverseChronologicalLogLines
					if len(logLines) < 20 {
						return false, fmt.Errorf("got %d log lines, waiting for at least 10", len(logLines))
					}
					consecutiveSameZone := 0

					for _, logLine := range logLines {
						if logLine == "" || strings.HasPrefix(logLine, "Date:") {
							continue
						}
						destZone, ok := zoneForServingPod[logLine]
						if !ok {
							return false, fmt.Errorf("could not determine dest zone from log line: %s", logLine)
						}
						if clientZone != destZone {
							return false, fmt.Errorf("expected request from clientPod=%q to stay in it's zone=%q, delivered to zone=%q", clientPod.Name, clientZone, destZone)
						}
						consecutiveSameZone++
						if consecutiveSameZone >= 10 {
							return true, nil
						}
					}
					return false, nil
				})

				gomega.Eventually(ctx, requestsFromClient(clientPod)).WithPolling(5 * time.Second).WithTimeout(e2eservice.KubeProxyLagTimeout).Should(requestsSucceedAndStayInSameZone)
			}

			ginkgo.By("routing traffic cluster-wide, when there are no serving pods in the same zone as the client")

			clientZone := zones[2]
			framework.Logf("creating a client pod for probing the service from zone=%q which DOES NOT has a serving pod", clientZone)
			clientPod := createClientPod(ctx, clientZone)

			framework.Logf("ensuring that requests from clientPod=%q on zone=%q (without a serving pod) are not dropped, and get routed to one of the serving pods anywhere in the cluster", clientPod.Name, clientZone)

			requestsSucceedByReachingAnyServingPod := gcustom.MakeMatcher(func(reverseChronologicalLogLines []string) (bool, error) {
				logLines := reverseChronologicalLogLines
				if len(logLines) < 20 {
					return false, fmt.Errorf("got %d log lines, waiting for at least 10", len(logLines))
				}

				// Requests are counted as successful when the response read from the log
				// lines is the name of a recognizable serving pod.
				consecutiveSuccessfulRequests := 0

				for _, logLine := range logLines {
					if logLine == "" || strings.HasPrefix(logLine, "Date:") {
						continue
					}
					_, servingPodExists := zoneForServingPod[logLine]
					if !servingPodExists {
						return false, fmt.Errorf("request from client pod likely failed because we got an unrecognizable response = %v; want response to be one of the serving pod names", logLine)
					}
					consecutiveSuccessfulRequests++
					if consecutiveSuccessfulRequests >= 10 {
						return true, nil
					}
				}
				return false, nil
			})

			gomega.Eventually(ctx, requestsFromClient(clientPod)).WithPolling(5 * time.Second).WithTimeout(e2eservice.KubeProxyLagTimeout).Should(requestsSucceedByReachingAnyServingPod)

		})

	})
})
