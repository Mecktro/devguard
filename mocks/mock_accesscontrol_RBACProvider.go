// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	accesscontrol "github.com/l3montree-dev/devguard/internal/accesscontrol"
	mock "github.com/stretchr/testify/mock"
)

// AccesscontrolRBACProvider is an autogenerated mock type for the RBACProvider type
type AccesscontrolRBACProvider struct {
	mock.Mock
}

type AccesscontrolRBACProvider_Expecter struct {
	mock *mock.Mock
}

func (_m *AccesscontrolRBACProvider) EXPECT() *AccesscontrolRBACProvider_Expecter {
	return &AccesscontrolRBACProvider_Expecter{mock: &_m.Mock}
}

// DomainsOfUser provides a mock function with given fields: user
func (_m *AccesscontrolRBACProvider) DomainsOfUser(user string) ([]string, error) {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for DomainsOfUser")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]string, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolRBACProvider_DomainsOfUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DomainsOfUser'
type AccesscontrolRBACProvider_DomainsOfUser_Call struct {
	*mock.Call
}

// DomainsOfUser is a helper method to define mock.On call
//   - user string
func (_e *AccesscontrolRBACProvider_Expecter) DomainsOfUser(user interface{}) *AccesscontrolRBACProvider_DomainsOfUser_Call {
	return &AccesscontrolRBACProvider_DomainsOfUser_Call{Call: _e.mock.On("DomainsOfUser", user)}
}

func (_c *AccesscontrolRBACProvider_DomainsOfUser_Call) Run(run func(user string)) *AccesscontrolRBACProvider_DomainsOfUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolRBACProvider_DomainsOfUser_Call) Return(_a0 []string, _a1 error) *AccesscontrolRBACProvider_DomainsOfUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolRBACProvider_DomainsOfUser_Call) RunAndReturn(run func(string) ([]string, error)) *AccesscontrolRBACProvider_DomainsOfUser_Call {
	_c.Call.Return(run)
	return _c
}

// GetDomainRBAC provides a mock function with given fields: domain
func (_m *AccesscontrolRBACProvider) GetDomainRBAC(domain string) accesscontrol.AccessControl {
	ret := _m.Called(domain)

	if len(ret) == 0 {
		panic("no return value specified for GetDomainRBAC")
	}

	var r0 accesscontrol.AccessControl
	if rf, ok := ret.Get(0).(func(string) accesscontrol.AccessControl); ok {
		r0 = rf(domain)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(accesscontrol.AccessControl)
		}
	}

	return r0
}

// AccesscontrolRBACProvider_GetDomainRBAC_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDomainRBAC'
type AccesscontrolRBACProvider_GetDomainRBAC_Call struct {
	*mock.Call
}

// GetDomainRBAC is a helper method to define mock.On call
//   - domain string
func (_e *AccesscontrolRBACProvider_Expecter) GetDomainRBAC(domain interface{}) *AccesscontrolRBACProvider_GetDomainRBAC_Call {
	return &AccesscontrolRBACProvider_GetDomainRBAC_Call{Call: _e.mock.On("GetDomainRBAC", domain)}
}

func (_c *AccesscontrolRBACProvider_GetDomainRBAC_Call) Run(run func(domain string)) *AccesscontrolRBACProvider_GetDomainRBAC_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolRBACProvider_GetDomainRBAC_Call) Return(_a0 accesscontrol.AccessControl) *AccesscontrolRBACProvider_GetDomainRBAC_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolRBACProvider_GetDomainRBAC_Call) RunAndReturn(run func(string) accesscontrol.AccessControl) *AccesscontrolRBACProvider_GetDomainRBAC_Call {
	_c.Call.Return(run)
	return _c
}

// NewAccesscontrolRBACProvider creates a new instance of AccesscontrolRBACProvider. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAccesscontrolRBACProvider(t interface {
	mock.TestingT
	Cleanup(func())
}) *AccesscontrolRBACProvider {
	mock := &AccesscontrolRBACProvider{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
