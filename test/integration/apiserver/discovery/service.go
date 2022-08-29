package discovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/client-go/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
)

type FakeService interface {
	Start(t *testing.T, ctx context.Context)
	Port() *int32
	Name() string
}

// Creates and registers an in-process Service capable of communicating with the
// kubernetes integration test apiserver
type fakeService struct {
	name    string
	client  kubernetes.Interface
	handler http.Handler

	lock       sync.RWMutex
	activePort *int32
}

func NewFakeService(name string, client kubernetes.Interface, handler http.Handler) *fakeService {
	return &fakeService{
		name:    name,
		client:  client,
		handler: handler,
	}
}

func (f *fakeService) run(ctx context.Context) error {
	aggregatedServer := httptest.NewUnstartedServer(f.handler)
	aggregatedServer.StartTLS()
	defer aggregatedServer.Close()

	serverURL, err := url.Parse(aggregatedServer.URL)
	if err != nil {
		// This should never occur
		panic(err)
	}

	serverPort, err := strconv.Atoi(serverURL.Port())
	if err != nil {
		// This should never occur
		panic(err)
	}

	port := int32(serverPort)

	// Install service into the cluster
	service, err := f.client.CoreV1().Services("default").Apply(
		ctx,
		corev1apply.Service(f.name, "default").
			WithSpec(corev1apply.ServiceSpec().
				WithPorts(
					corev1apply.ServicePort().
						WithPort(port)).
				WithType("ExternalName").
				WithExternalName("localhost")),
		metav1.ApplyOptions{
			FieldManager: "test-manager",
		},
	)
	if err != nil {
		return err
	}

	f.lock.Lock()
	f.activePort = &port
	f.lock.Unlock()

	<-ctx.Done()

	f.lock.Lock()
	f.activePort = nil
	f.lock.Unlock()

	// Uninstall service from the cluser
	err = f.client.CoreV1().Services("default").Delete(ctx, service.Name, metav1.DeleteOptions{})
	return err
}

func (f *fakeService) Start(t *testing.T, ctx context.Context) {
	go func() {
		err := f.run(ctx)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		require.NoError(t, err)
	}()

	err := wait.PollWithContext(ctx, 1*time.Second, 200*time.Millisecond, func(ctx context.Context) (done bool, err error) {
		return f.Port() != nil, nil
	})

	if errors.Is(err, context.Canceled) {
		err = nil
	}
	require.NoError(t, err, "service should have come alive in a reasonable amount of time")
}

func (f *fakeService) Port() *int32 {
	// Returns the port of the server if it is running or nil
	// if it is not running
	f.lock.RLock()
	defer f.lock.RUnlock()
	return f.activePort
}

func (f *fakeService) Name() string {
	return f.name
}
