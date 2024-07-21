// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// ScanComparer is an autogenerated mock type for the comparer type
type ScanComparer struct {
	mock.Mock
}

type ScanComparer_Expecter struct {
	mock *mock.Mock
}

func (_m *ScanComparer) EXPECT() *ScanComparer_Expecter {
	return &ScanComparer_Expecter{mock: &_m.Mock}
}

// GetVulns provides a mock function with given fields: purl
func (_m *ScanComparer) GetVulns(purl string) ([]models.VulnInPackage, error) {
	ret := _m.Called(purl)

	if len(ret) == 0 {
		panic("no return value specified for GetVulns")
	}

	var r0 []models.VulnInPackage
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]models.VulnInPackage, error)); ok {
		return rf(purl)
	}
	if rf, ok := ret.Get(0).(func(string) []models.VulnInPackage); ok {
		r0 = rf(purl)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.VulnInPackage)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(purl)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ScanComparer_GetVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetVulns'
type ScanComparer_GetVulns_Call struct {
	*mock.Call
}

// GetVulns is a helper method to define mock.On call
//   - purl string
func (_e *ScanComparer_Expecter) GetVulns(purl interface{}) *ScanComparer_GetVulns_Call {
	return &ScanComparer_GetVulns_Call{Call: _e.mock.On("GetVulns", purl)}
}

func (_c *ScanComparer_GetVulns_Call) Run(run func(purl string)) *ScanComparer_GetVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *ScanComparer_GetVulns_Call) Return(_a0 []models.VulnInPackage, _a1 error) *ScanComparer_GetVulns_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ScanComparer_GetVulns_Call) RunAndReturn(run func(string) ([]models.VulnInPackage, error)) *ScanComparer_GetVulns_Call {
	_c.Call.Return(run)
	return _c
}

// NewScanComparer creates a new instance of ScanComparer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewScanComparer(t interface {
	mock.TestingT
	Cleanup(func())
}) *ScanComparer {
	mock := &ScanComparer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
