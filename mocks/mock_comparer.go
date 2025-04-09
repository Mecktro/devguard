// Code generated by mockery v2.53.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// Comparer is an autogenerated mock type for the comparer type
type Comparer struct {
	mock.Mock
}

type Comparer_Expecter struct {
	mock *mock.Mock
}

func (_m *Comparer) EXPECT() *Comparer_Expecter {
	return &Comparer_Expecter{mock: &_m.Mock}
}

// GetVulns provides a mock function with given fields: purl, notASemverVersion, componentType
func (_m *Comparer) GetVulns(purl string, notASemverVersion string, componentType string) ([]models.VulnInPackage, error) {
	ret := _m.Called(purl, notASemverVersion, componentType)

	if len(ret) == 0 {
		panic("no return value specified for GetVulns")
	}

	var r0 []models.VulnInPackage
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string, string) ([]models.VulnInPackage, error)); ok {
		return rf(purl, notASemverVersion, componentType)
	}
	if rf, ok := ret.Get(0).(func(string, string, string) []models.VulnInPackage); ok {
		r0 = rf(purl, notASemverVersion, componentType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.VulnInPackage)
		}
	}

	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(purl, notASemverVersion, componentType)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Comparer_GetVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetVulns'
type Comparer_GetVulns_Call struct {
	*mock.Call
}

// GetVulns is a helper method to define mock.On call
//   - purl string
//   - notASemverVersion string
//   - componentType string
func (_e *Comparer_Expecter) GetVulns(purl interface{}, notASemverVersion interface{}, componentType interface{}) *Comparer_GetVulns_Call {
	return &Comparer_GetVulns_Call{Call: _e.mock.On("GetVulns", purl, notASemverVersion, componentType)}
}

func (_c *Comparer_GetVulns_Call) Run(run func(purl string, notASemverVersion string, componentType string)) *Comparer_GetVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *Comparer_GetVulns_Call) Return(_a0 []models.VulnInPackage, _a1 error) *Comparer_GetVulns_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Comparer_GetVulns_Call) RunAndReturn(run func(string, string, string) ([]models.VulnInPackage, error)) *Comparer_GetVulns_Call {
	_c.Call.Return(run)
	return _c
}

// NewComparer creates a new instance of Comparer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewComparer(t interface {
	mock.TestingT
	Cleanup(func())
}) *Comparer {
	mock := &Comparer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
