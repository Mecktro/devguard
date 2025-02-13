// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	echo "github.com/labstack/echo/v4"
	mock "github.com/stretchr/testify/mock"
)

// CoreMiddlewareFunc is an autogenerated mock type for the MiddlewareFunc type
type CoreMiddlewareFunc struct {
	mock.Mock
}

type CoreMiddlewareFunc_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreMiddlewareFunc) EXPECT() *CoreMiddlewareFunc_Expecter {
	return &CoreMiddlewareFunc_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: next
func (_m *CoreMiddlewareFunc) Execute(next echo.HandlerFunc) echo.HandlerFunc {
	ret := _m.Called(next)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 echo.HandlerFunc
	if rf, ok := ret.Get(0).(func(echo.HandlerFunc) echo.HandlerFunc); ok {
		r0 = rf(next)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(echo.HandlerFunc)
		}
	}

	return r0
}

// CoreMiddlewareFunc_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type CoreMiddlewareFunc_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - next echo.HandlerFunc
func (_e *CoreMiddlewareFunc_Expecter) Execute(next interface{}) *CoreMiddlewareFunc_Execute_Call {
	return &CoreMiddlewareFunc_Execute_Call{Call: _e.mock.On("Execute", next)}
}

func (_c *CoreMiddlewareFunc_Execute_Call) Run(run func(next echo.HandlerFunc)) *CoreMiddlewareFunc_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.HandlerFunc))
	})
	return _c
}

func (_c *CoreMiddlewareFunc_Execute_Call) Return(_a0 echo.HandlerFunc) *CoreMiddlewareFunc_Execute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreMiddlewareFunc_Execute_Call) RunAndReturn(run func(echo.HandlerFunc) echo.HandlerFunc) *CoreMiddlewareFunc_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreMiddlewareFunc creates a new instance of CoreMiddlewareFunc. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreMiddlewareFunc(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreMiddlewareFunc {
	mock := &CoreMiddlewareFunc{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
