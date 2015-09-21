/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package cache

import (
	"reflect"
	"testing"
	"time"

	"k8s.io/kubernetes/pkg/util"
	"k8s.io/kubernetes/pkg/util/sets"
)

func TestTTLExpirationBasic(t *testing.T) {
	testObj := testStoreObject{id: "foo", val: "bar"}
	deleteChan := make(chan string)
	ttlStore := NewFakeExpirationStore(
		testStoreKeyFunc, deleteChan,
		&FakeExpirationPolicy{
			NeverExpire: sets.NewString(),
			RetrieveKeyFunc: func(obj interface{}) (string, error) {
				return obj.(*timestampedEntry).obj.(testStoreObject).id, nil
			},
		},
		util.RealClock{},
	)
	err := ttlStore.Add(testObj)
	if err != nil {
		t.Errorf("Unable to add obj %#v", testObj)
	}
	item, exists, err := ttlStore.Get(testObj)
	if err != nil {
		t.Errorf("Failed to get from store, %v", err)
	}
	if exists || item != nil {
		t.Errorf("Got unexpected item %#v", item)
	}
	key, _ := testStoreKeyFunc(testObj)
	select {
	case delKey := <-deleteChan:
		if delKey != key {
			t.Errorf("Unexpected delete for key %s", key)
		}
	case <-time.After(time.Millisecond * 100):
		t.Errorf("Unexpected timeout waiting on delete")
	}
	close(deleteChan)
}

func TestTTLList(t *testing.T) {
	testObjs := []testStoreObject{
		{id: "foo", val: "bar"},
		{id: "foo1", val: "bar1"},
		{id: "foo2", val: "bar2"},
	}
	expireKeys := sets.NewString(testObjs[0].id, testObjs[2].id)
	deleteChan := make(chan string)
	defer close(deleteChan)

	ttlStore := NewFakeExpirationStore(
		testStoreKeyFunc, deleteChan,
		&FakeExpirationPolicy{
			NeverExpire: sets.NewString(testObjs[1].id),
			RetrieveKeyFunc: func(obj interface{}) (string, error) {
				return obj.(*timestampedEntry).obj.(testStoreObject).id, nil
			},
		},
		util.RealClock{},
	)
	for _, obj := range testObjs {
		err := ttlStore.Add(obj)
		if err != nil {
			t.Errorf("Unable to add obj %#v", obj)
		}
	}
	listObjs := ttlStore.List()
	if len(listObjs) != 1 || !reflect.DeepEqual(listObjs[0], testObjs[1]) {
		t.Errorf("List returned unexpected results %#v", listObjs)
	}

	// Make sure all our deletes come through in an acceptable rate (1/100ms)
	for expireKeys.Len() != 0 {
		select {
		case delKey := <-deleteChan:
			if !expireKeys.Has(delKey) {
				t.Errorf("Unexpected delete for key %s", delKey)
			}
			expireKeys.Delete(delKey)
		case <-time.After(time.Millisecond * 100):
			t.Errorf("Unexpected timeout waiting on delete")
			return
		}
	}
}

func TestTTLPolicy(t *testing.T) {
	fakeTime := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	ttl := 30 * time.Second
	exactlyOnTTL := fakeTime.Add(-ttl)
	expiredTime := fakeTime.Add(-(ttl + 1))

	policy := TTLPolicy{ttl, &util.FakeClock{Time: fakeTime}}
	fakeTimestampedEntry := &timestampedEntry{obj: struct{}{}, timestamp: exactlyOnTTL}
	if policy.IsExpired(fakeTimestampedEntry) {
		t.Errorf("TTL cache should not expire entries exactly on ttl")
	}
	fakeTimestampedEntry.timestamp = fakeTime
	if policy.IsExpired(fakeTimestampedEntry) {
		t.Errorf("TTL Cache should not expire entries before ttl")
	}
	fakeTimestampedEntry.timestamp = expiredTime
	if !policy.IsExpired(fakeTimestampedEntry) {
		t.Errorf("TTL Cache should expire entries older than ttl")
	}
	for _, ttl = range []time.Duration{0, -1} {
		policy.Ttl = ttl
		if policy.IsExpired(fakeTimestampedEntry) {
			t.Errorf("TTL policy should only expire entries when initialized with a ttl > 0")
		}
	}
}
