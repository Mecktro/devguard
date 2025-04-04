// Code generated by mockery v2.53.2. DO NOT EDIT.

package mocks

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	mock "github.com/stretchr/testify/mock"
)

// SBOM is an autogenerated mock type for the SBOM type
type SBOM struct {
	mock.Mock
}

type SBOM_Expecter struct {
	mock *mock.Mock
}

func (_m *SBOM) EXPECT() *SBOM_Expecter {
	return &SBOM_Expecter{mock: &_m.Mock}
}

// GetComponents provides a mock function with no fields
func (_m *SBOM) GetComponents() *[]cyclonedx.Component {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetComponents")
	}

	var r0 *[]cyclonedx.Component
	if rf, ok := ret.Get(0).(func() *[]cyclonedx.Component); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*[]cyclonedx.Component)
		}
	}

	return r0
}

// SBOM_GetComponents_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetComponents'
type SBOM_GetComponents_Call struct {
	*mock.Call
}

// GetComponents is a helper method to define mock.On call
func (_e *SBOM_Expecter) GetComponents() *SBOM_GetComponents_Call {
	return &SBOM_GetComponents_Call{Call: _e.mock.On("GetComponents")}
}

func (_c *SBOM_GetComponents_Call) Run(run func()) *SBOM_GetComponents_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *SBOM_GetComponents_Call) Return(_a0 *[]cyclonedx.Component) *SBOM_GetComponents_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *SBOM_GetComponents_Call) RunAndReturn(run func() *[]cyclonedx.Component) *SBOM_GetComponents_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencies provides a mock function with no fields
func (_m *SBOM) GetDependencies() *[]cyclonedx.Dependency {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetDependencies")
	}

	var r0 *[]cyclonedx.Dependency
	if rf, ok := ret.Get(0).(func() *[]cyclonedx.Dependency); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*[]cyclonedx.Dependency)
		}
	}

	return r0
}

// SBOM_GetDependencies_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencies'
type SBOM_GetDependencies_Call struct {
	*mock.Call
}

// GetDependencies is a helper method to define mock.On call
func (_e *SBOM_Expecter) GetDependencies() *SBOM_GetDependencies_Call {
	return &SBOM_GetDependencies_Call{Call: _e.mock.On("GetDependencies")}
}

func (_c *SBOM_GetDependencies_Call) Run(run func()) *SBOM_GetDependencies_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *SBOM_GetDependencies_Call) Return(_a0 *[]cyclonedx.Dependency) *SBOM_GetDependencies_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *SBOM_GetDependencies_Call) RunAndReturn(run func() *[]cyclonedx.Dependency) *SBOM_GetDependencies_Call {
	_c.Call.Return(run)
	return _c
}

// GetMetadata provides a mock function with no fields
func (_m *SBOM) GetMetadata() *cyclonedx.Metadata {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetMetadata")
	}

	var r0 *cyclonedx.Metadata
	if rf, ok := ret.Get(0).(func() *cyclonedx.Metadata); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*cyclonedx.Metadata)
		}
	}

	return r0
}

// SBOM_GetMetadata_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetMetadata'
type SBOM_GetMetadata_Call struct {
	*mock.Call
}

// GetMetadata is a helper method to define mock.On call
func (_e *SBOM_Expecter) GetMetadata() *SBOM_GetMetadata_Call {
	return &SBOM_GetMetadata_Call{Call: _e.mock.On("GetMetadata")}
}

func (_c *SBOM_GetMetadata_Call) Run(run func()) *SBOM_GetMetadata_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *SBOM_GetMetadata_Call) Return(_a0 *cyclonedx.Metadata) *SBOM_GetMetadata_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *SBOM_GetMetadata_Call) RunAndReturn(run func() *cyclonedx.Metadata) *SBOM_GetMetadata_Call {
	_c.Call.Return(run)
	return _c
}

// NewSBOM creates a new instance of SBOM. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSBOM(t interface {
	mock.TestingT
	Cleanup(func())
}) *SBOM {
	mock := &SBOM{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
