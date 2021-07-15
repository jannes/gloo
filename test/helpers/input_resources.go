package helpers

import (
	"fmt"
	"reflect"
	"time"

	"github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	errors "github.com/rotisserie/eris"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources/core"
	skerrors "github.com/solo-io/solo-kit/pkg/errors"
)

const (
	defaultEventuallyTimeout         = 15 * time.Second
	defaultEventuallyPollingInterval = 1 * time.Second
)

type InputResourceGetter func() (resources.InputResource, error)
type InputResourceListGetter func() (resources.InputResourceList, error)

func EventuallyResourceAccepted(getter InputResourceGetter, intervals ...interface{}) {
	EventuallyResourceStatusMatchesState(1, getter, core.Status_Accepted, intervals)
}

func EventuallyResourceRejected(getter InputResourceGetter, intervals ...interface{}) {
	EventuallyResourceStatusMatchesState(1, getter, core.Status_Rejected, intervals)
}

func EventuallyResourceWarning(getter InputResourceGetter, intervals ...interface{}) {
	EventuallyResourceStatusMatchesState(1, getter, core.Status_Warning, intervals)
}

func EventuallyResourceStatusMatchesState(offset int, getter InputResourceGetter, statusState core.Status_State, intervals ...interface{}) {
	statusStateMatcher := gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"State": gomega.Equal(statusState),
	})

	timeoutInterval, pollingInterval := getTimeoutAndPollingIntervalsOrDefault(intervals)
	gomega.EventuallyWithOffset(offset+1, func() (core.Status, error) {
		resource, err := getter()
		if err != nil {
			return core.Status{}, errors.Wrapf(err, "failed to get resource")
		}

		if resource.GetStatus() == nil {
			return core.Status{}, errors.Wrapf(err, "waiting for %v status to be non-nil", resource.GetMetadata().GetName())
		}

		return *resource.GetStatus(), nil
	}, timeoutInterval, pollingInterval).Should(statusStateMatcher)
}

func EventuallyResourceDeleted(getter InputResourceGetter, intervals ...interface{}) {
	EventuallyResourceDeletedWithOffset(1, getter, intervals...)
}

func EventuallyResourceDeletedWithOffset(offset int, getter InputResourceGetter, intervals ...interface{}) {
	timeoutInterval, pollingInterval := getTimeoutAndPollingIntervalsOrDefault(intervals)
	gomega.EventuallyWithOffset(offset+1, func() (bool, error) {
		_, err := getter()
		if err != nil && skerrors.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}, timeoutInterval, pollingInterval).Should(gomega.BeTrue())
}

func getTimeoutAndPollingIntervalsOrDefault(intervals ...interface{}) (time.Duration, time.Duration) {
	timeoutInterval := defaultEventuallyTimeout
	pollingInterval := defaultEventuallyPollingInterval
	if len(intervals) > 0 {
		timeoutInterval = toDuration(intervals[0])
	}
	if len(intervals) > 1 {
		pollingInterval = toDuration(intervals[1])
	}

	return timeoutInterval, pollingInterval
}

// copied from: https://github.com/onsi/gomega/blob/abcfad1fbdcd525712c9639dec0659c584cf4290/gomega_dsl.go#L485
func toDuration(input interface{}) time.Duration {
	duration, ok := input.(time.Duration)
	if ok {
		return duration
	}

	value := reflect.ValueOf(input)
	kind := reflect.TypeOf(input).Kind()

	if reflect.Int <= kind && kind <= reflect.Int64 {
		return time.Duration(value.Int()) * time.Second
	} else if reflect.Uint <= kind && kind <= reflect.Uint64 {
		return time.Duration(value.Uint()) * time.Second
	} else if reflect.Float32 <= kind && kind <= reflect.Float64 {
		return time.Duration(value.Float() * float64(time.Second))
	} else if reflect.String == kind {
		duration, err := time.ParseDuration(value.String())
		if err != nil {
			panic(fmt.Sprintf("%#v is not a valid parsable duration string.", input))
		}
		return duration
	}

	panic(fmt.Sprintf("%v is not a valid interval.  Must be time.Duration, parsable duration string or a number.", input))
}
