package helpers

import (
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	errors "github.com/rotisserie/eris"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources/core"
	skerrors "github.com/solo-io/solo-kit/pkg/errors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type InputResourceGetter func() (resources.InputResource, error)
type InputResourceListGetter func() (resources.InputResourceList, error)
type ObjectGetter func() (client.Object, error)

func EventuallyResourceAccepted(getter InputResourceGetter) {
	EventuallyResourceAcceptedWithOffset(1, getter)
}

func EventuallyResourceAcceptedWithOffset(ginkgoOffset int, getter InputResourceGetter) {
	gomega.EventuallyWithOffset(ginkgoOffset+1, func() (core.Status, error) {
		resource, err := getter()
		if err != nil || resource.GetStatus() == nil {
			return core.Status{}, errors.Wrapf(err, "waiting for %v to be accepted, but status is %v", resource.GetMetadata().GetName(), resource.GetStatus())
		}

		return *resource.GetStatus(), nil
	}, "15s", "0.5s").Should(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Reason": gomega.BeEmpty(),
		"State":  gomega.Equal(core.Status_Accepted),
	}))
}

func EventuallyResourceDeleted(getter InputResourceGetter, intervals ...interface{}) {
	EventuallyResourceDeletedWithOffset(1, getter, intervals...)
}

func EventuallyResourceDeletedWithOffset(ginkgoOffset int, getter InputResourceGetter, intervals ...interface{}) {
	gomega.EventuallyWithOffset(ginkgoOffset+1, func() (bool, error) {
		_, err := getter()
		if err != nil && skerrors.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}, intervals...).Should(gomega.BeTrue())
}

func EventuallyObjectDeleted(getter ObjectGetter, intervals ...interface{}) {
	gomega.Eventually(func() (bool, error) {
		_, err := getter()
		if err != nil && k8serrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}, intervals...).Should(gomega.BeTrue())
}
