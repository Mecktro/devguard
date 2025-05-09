// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	context "context"

	client "github.com/ory/client-go"

	mock "github.com/stretchr/testify/mock"
)

// AdminClient is an autogenerated mock type for the AdminClient type
type AdminClient struct {
	mock.Mock
}

type AdminClient_Expecter struct {
	mock *mock.Mock
}

func (_m *AdminClient) EXPECT() *AdminClient_Expecter {
	return &AdminClient_Expecter{mock: &_m.Mock}
}

// GetIdentity provides a mock function with given fields: ctx, userID
func (_m *AdminClient) GetIdentity(ctx context.Context, userID string) (client.Identity, error) {
	ret := _m.Called(ctx, userID)

	if len(ret) == 0 {
		panic("no return value specified for GetIdentity")
	}

	var r0 client.Identity
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (client.Identity, error)); ok {
		return rf(ctx, userID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) client.Identity); ok {
		r0 = rf(ctx, userID)
	} else {
		r0 = ret.Get(0).(client.Identity)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AdminClient_GetIdentity_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetIdentity'
type AdminClient_GetIdentity_Call struct {
	*mock.Call
}

// GetIdentity is a helper method to define mock.On call
//   - ctx context.Context
//   - userID string
func (_e *AdminClient_Expecter) GetIdentity(ctx interface{}, userID interface{}) *AdminClient_GetIdentity_Call {
	return &AdminClient_GetIdentity_Call{Call: _e.mock.On("GetIdentity", ctx, userID)}
}

func (_c *AdminClient_GetIdentity_Call) Run(run func(ctx context.Context, userID string)) *AdminClient_GetIdentity_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *AdminClient_GetIdentity_Call) Return(_a0 client.Identity, _a1 error) *AdminClient_GetIdentity_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AdminClient_GetIdentity_Call) RunAndReturn(run func(context.Context, string) (client.Identity, error)) *AdminClient_GetIdentity_Call {
	_c.Call.Return(run)
	return _c
}

// ListUser provides a mock function with given fields: _a0
func (_m *AdminClient) ListUser(_a0 client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error) {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for ListUser")
	}

	var r0 []client.Identity
	var r1 error
	if rf, ok := ret.Get(0).(func(client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(client.IdentityAPIListIdentitiesRequest) []client.Identity); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.Identity)
		}
	}

	if rf, ok := ret.Get(1).(func(client.IdentityAPIListIdentitiesRequest) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AdminClient_ListUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListUser'
type AdminClient_ListUser_Call struct {
	*mock.Call
}

// ListUser is a helper method to define mock.On call
//   - _a0 client.IdentityAPIListIdentitiesRequest
func (_e *AdminClient_Expecter) ListUser(_a0 interface{}) *AdminClient_ListUser_Call {
	return &AdminClient_ListUser_Call{Call: _e.mock.On("ListUser", _a0)}
}

func (_c *AdminClient_ListUser_Call) Run(run func(_a0 client.IdentityAPIListIdentitiesRequest)) *AdminClient_ListUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(client.IdentityAPIListIdentitiesRequest))
	})
	return _c
}

func (_c *AdminClient_ListUser_Call) Return(_a0 []client.Identity, _a1 error) *AdminClient_ListUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AdminClient_ListUser_Call) RunAndReturn(run func(client.IdentityAPIListIdentitiesRequest) ([]client.Identity, error)) *AdminClient_ListUser_Call {
	_c.Call.Return(run)
	return _c
}

// NewAdminClient creates a new instance of AdminClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAdminClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *AdminClient {
	mock := &AdminClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
