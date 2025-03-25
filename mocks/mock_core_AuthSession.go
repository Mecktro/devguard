// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// CoreAuthSession is an autogenerated mock type for the AuthSession type
type CoreAuthSession struct {
	mock.Mock
}

type CoreAuthSession_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreAuthSession) EXPECT() *CoreAuthSession_Expecter {
	return &CoreAuthSession_Expecter{mock: &_m.Mock}
}

// GetUserID provides a mock function with no fields
func (_m *CoreAuthSession) GetUserID() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetUserID")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// CoreAuthSession_GetUserID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserID'
type CoreAuthSession_GetUserID_Call struct {
	*mock.Call
}

// GetUserID is a helper method to define mock.On call
func (_e *CoreAuthSession_Expecter) GetUserID() *CoreAuthSession_GetUserID_Call {
	return &CoreAuthSession_GetUserID_Call{Call: _e.mock.On("GetUserID")}
}

func (_c *CoreAuthSession_GetUserID_Call) Run(run func()) *CoreAuthSession_GetUserID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreAuthSession_GetUserID_Call) Return(_a0 string) *CoreAuthSession_GetUserID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAuthSession_GetUserID_Call) RunAndReturn(run func() string) *CoreAuthSession_GetUserID_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreAuthSession creates a new instance of CoreAuthSession. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreAuthSession(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreAuthSession {
	mock := &CoreAuthSession{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
