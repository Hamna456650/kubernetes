/*
Copyright 2015 The Kubernetes Authors.

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

package volume

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/api/resource"
	"k8s.io/kubernetes/pkg/watch"
)

type testcase struct {
	name          string
	existingPod   *api.Pod
	createPod     *api.Pod
	eventSequence []watch.Event

	expectedEvents []mockEvent
	expectedError  string
}

func newPodEvent(eventtype watch.EventType, name string, phase api.PodPhase, message string) watch.Event {
	return watch.Event{
		Type:   eventtype,
		Object: newPod(name, phase, message),
	}
}

func newEvent(eventtype, message string) watch.Event {
	return watch.Event{
		Type: watch.Added,
		Object: &api.Event{
			ObjectMeta: api.ObjectMeta{
				Namespace: api.NamespaceDefault,
			},
			Reason:  "MockEvent",
			Message: message,
			Type:    eventtype,
		},
	}
}

func newPod(name string, phase api.PodPhase, message string) *api.Pod {
	return &api.Pod{
		ObjectMeta: api.ObjectMeta{
			Namespace: api.NamespaceDefault,
			Name:      name,
		},
		Status: api.PodStatus{
			Phase:   phase,
			Message: message,
		},
	}
}

func TestRecyclerPod(t *testing.T) {
	tests := []testcase{
		{
			// Test recycler success with some events
			name:      "RecyclerSuccess",
			createPod: newPod("podRecyclerSuccess", api.PodPending, ""),
			eventSequence: []watch.Event{
				// Pod gets Running and Succeeded
				newPodEvent(watch.Added, "podRecyclerSuccess", api.PodPending, ""),
				newEvent(api.EventTypeNormal, "Successfully assigned recycler-for-podRecyclerSuccess to 127.0.0.1"),
				newEvent(api.EventTypeNormal, "pulling image \"gcr.io/google_containers/busybox\""),
				newEvent(api.EventTypeNormal, "Successfully pulled image \"gcr.io/google_containers/busybox\""),
				newEvent(api.EventTypeNormal, "Created container with docker id 83d929aeac82"),
				newEvent(api.EventTypeNormal, "Started container with docker id 83d929aeac82"),
				newPodEvent(watch.Modified, "podRecyclerSuccess", api.PodRunning, ""),
				newPodEvent(watch.Modified, "podRecyclerSuccess", api.PodSucceeded, ""),
			},
			expectedEvents: []mockEvent{
				{api.EventTypeNormal, "Successfully assigned recycler-for-podRecyclerSuccess to 127.0.0.1"},
				{api.EventTypeNormal, "pulling image \"gcr.io/google_containers/busybox\""},
				{api.EventTypeNormal, "Successfully pulled image \"gcr.io/google_containers/busybox\""},
				{api.EventTypeNormal, "Created container with docker id 83d929aeac82"},
				{api.EventTypeNormal, "Started container with docker id 83d929aeac82"},
			},
			expectedError: "",
		},
		{
			// Test recycler failure with some events
			name:      "RecyclerFailure",
			createPod: newPod("podRecyclerFailure", api.PodPending, ""),
			eventSequence: []watch.Event{
				// Pod gets Running and Succeeded
				newPodEvent(watch.Added, "podRecyclerFailure", api.PodPending, ""),
				newEvent(api.EventTypeNormal, "Successfully assigned recycler-for-podRecyclerFailure to 127.0.0.1"),
				newEvent(api.EventTypeWarning, "Unable to mount volumes for pod \"recycler-for-podRecyclerFailure_default(3c9809e5-347c-11e6-a79b-3c970e965218)\": timeout expired waiting for volumes to attach/mount"),
				newEvent(api.EventTypeWarning, "Error syncing pod, skipping: timeout expired waiting for volumes to attach/mount for pod \"recycler-for-podRecyclerFailure\"/\"default\". list of unattached/unmounted"),
				newPodEvent(watch.Modified, "podRecyclerFailure", api.PodRunning, ""),
				newPodEvent(watch.Modified, "podRecyclerFailure", api.PodFailed, "Pod was active on the node longer than specified deadline"),
			},
			expectedEvents: []mockEvent{
				{api.EventTypeNormal, "Successfully assigned recycler-for-podRecyclerFailure to 127.0.0.1"},
				{api.EventTypeWarning, "Unable to mount volumes for pod \"recycler-for-podRecyclerFailure_default(3c9809e5-347c-11e6-a79b-3c970e965218)\": timeout expired waiting for volumes to attach/mount"},
				{api.EventTypeWarning, "Error syncing pod, skipping: timeout expired waiting for volumes to attach/mount for pod \"recycler-for-podRecyclerFailure\"/\"default\". list of unattached/unmounted"},
			},
			expectedError: "Pod was active on the node longer than specified deadline",
		},
		{
			// Recycler pod gets deleted
			name:      "RecyclerDeleted",
			createPod: newPod("podRecyclerDeleted", api.PodPending, ""),
			eventSequence: []watch.Event{
				// Pod gets Running and Succeeded
				newPodEvent(watch.Added, "podRecyclerDeleted", api.PodPending, ""),
				newEvent(api.EventTypeNormal, "Successfully assigned recycler-for-podRecyclerDeleted to 127.0.0.1"),
				newPodEvent(watch.Deleted, "podRecyclerDeleted", api.PodPending, ""),
			},
			expectedEvents: []mockEvent{
				{api.EventTypeNormal, "Successfully assigned recycler-for-podRecyclerDeleted to 127.0.0.1"},
			},
			expectedError: "recycler pod was deleted",
		},
		{
			// Another recycler pod is already running
			name:        "RecyclerRunning",
			existingPod: newPod("podOldRecycler", api.PodRunning, ""),
			createPod:   newPod("podNewRecycler", api.PodFailed, "mock message"),
			eventSequence: []watch.Event{
				// Old pod succeeds
				newPodEvent(watch.Modified, "podOldRecycler", api.PodSucceeded, ""),
			},
			// No error = old pod succeeded. If the new pod was used, there
			// would be error with "mock message".
			expectedError: "",
		},
	}

	for _, test := range tests {
		t.Logf("Test %q", test.name)
		client := &mockRecyclerClient{
			events: test.eventSequence,
			pod:    test.existingPod,
		}
		err := internalRecycleVolumeByWatchingPodUntilCompletion(test.createPod.Name, test.createPod, client)
		receivedError := ""
		if err != nil {
			receivedError = err.Error()
		}
		if receivedError != test.expectedError {
			t.Errorf("Test %q failed, expected error %q, got %q", test.name, test.expectedError, receivedError)
		}
		if !client.deletedCalled {
			t.Errorf("Test %q failed, expected deferred client.Delete to be called on recycler pod", test.name)
		}
		for i, expectedEvent := range test.expectedEvents {
			if len(client.receivedEvents) <= i {
				t.Errorf("Test %q failed, expected event %d: %q not received", test.name, i, expectedEvent.message)
				continue
			}
			receivedEvent := client.receivedEvents[i]
			if expectedEvent.eventtype != receivedEvent.eventtype {
				t.Errorf("Test %q failed, event %d does not match: expected eventtype %q, got %q", test.name, i, expectedEvent.eventtype, receivedEvent.eventtype)
			}
			if expectedEvent.message != receivedEvent.message {
				t.Errorf("Test %q failed, event %d does not match: expected message %q, got %q", test.name, i, expectedEvent.message, receivedEvent.message)
			}
		}
		for i := len(test.expectedEvents); i < len(client.receivedEvents); i++ {
			t.Errorf("Test %q failed, unexpected event received: %s, %q", test.name, client.receivedEvents[i].eventtype, client.receivedEvents[i].message)
		}
	}
}

type mockRecyclerClient struct {
	pod            *api.Pod
	deletedCalled  bool
	receivedEvents []mockEvent
	events         []watch.Event
}

type mockEvent struct {
	eventtype, message string
}

func (c *mockRecyclerClient) CreatePod(pod *api.Pod) (*api.Pod, error) {
	if c.pod == nil {
		c.pod = pod
		return c.pod, nil
	}
	// Simulate "already exists" error
	return nil, errors.NewAlreadyExists(api.Resource("pods"), pod.Name)
}

func (c *mockRecyclerClient) GetPod(name, namespace string) (*api.Pod, error) {
	if c.pod != nil {
		return c.pod, nil
	} else {
		return nil, fmt.Errorf("pod does not exist")
	}
}

func (c *mockRecyclerClient) DeletePod(name, namespace string) error {
	c.deletedCalled = true
	return nil
}

func (c *mockRecyclerClient) WatchPod(name, namespace string, stopChannel chan struct{}) (<-chan watch.Event, error) {
	eventCh := make(chan watch.Event, 0)
	go func() {
		for _, e := range c.events {
			eventCh <- e
		}
	}()
	return eventCh, nil
}

func (c *mockRecyclerClient) Event(eventtype, message string) {
	c.receivedEvents = append(c.receivedEvents, mockEvent{eventtype, message})
}

func TestCalculateTimeoutForVolume(t *testing.T) {
	pv := &api.PersistentVolume{
		Spec: api.PersistentVolumeSpec{
			Capacity: api.ResourceList{
				api.ResourceName(api.ResourceStorage): resource.MustParse("500M"),
			},
		},
	}

	timeout := CalculateTimeoutForVolume(50, 30, pv)
	if timeout != 50 {
		t.Errorf("Expected 50 for timeout but got %v", timeout)
	}

	pv.Spec.Capacity[api.ResourceStorage] = resource.MustParse("2Gi")
	timeout = CalculateTimeoutForVolume(50, 30, pv)
	if timeout != 60 {
		t.Errorf("Expected 60 for timeout but got %v", timeout)
	}

	pv.Spec.Capacity[api.ResourceStorage] = resource.MustParse("150Gi")
	timeout = CalculateTimeoutForVolume(50, 30, pv)
	if timeout != 4500 {
		t.Errorf("Expected 4500 for timeout but got %v", timeout)
	}
}

func TestGenerateVolumeName(t *testing.T) {

	// Normal operation, no truncate
	v1 := GenerateVolumeName("kubernetes", "pv-cinder-abcde", 255)
	if v1 != "kubernetes-dynamic-pv-cinder-abcde" {
		t.Errorf("Expected kubernetes-dynamic-pv-cinder-abcde, got %s", v1)
	}

	// Truncate trailing "6789-dynamic"
	prefix := strings.Repeat("0123456789", 9) // 90 characters prefix + 8 chars. of "-dynamic"
	v2 := GenerateVolumeName(prefix, "pv-cinder-abcde", 100)
	expect := prefix[:84] + "-pv-cinder-abcde"
	if v2 != expect {
		t.Errorf("Expected %s, got %s", expect, v2)
	}

	// Truncate really long cluster name
	prefix = strings.Repeat("0123456789", 1000) // 10000 characters prefix
	v3 := GenerateVolumeName(prefix, "pv-cinder-abcde", 100)
	if v3 != expect {
		t.Errorf("Expected %s, got %s", expect, v3)
	}

}
