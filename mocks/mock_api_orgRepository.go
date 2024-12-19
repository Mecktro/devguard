// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// ApiOrgRepository is an autogenerated mock type for the orgRepository type
type ApiOrgRepository struct {
	mock.Mock
}

type ApiOrgRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ApiOrgRepository) EXPECT() *ApiOrgRepository_Expecter {
	return &ApiOrgRepository_Expecter{mock: &_m.Mock}
}

// ReadBySlug provides a mock function with given fields: slugOrId
func (_m *ApiOrgRepository) ReadBySlug(slugOrId string) (models.Org, error) {
	ret := _m.Called(slugOrId)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlug")
	}

	var r0 models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.Org, error)); ok {
		return rf(slugOrId)
	}
	if rf, ok := ret.Get(0).(func(string) models.Org); ok {
		r0 = rf(slugOrId)
	} else {
		r0 = ret.Get(0).(models.Org)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(slugOrId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ApiOrgRepository_ReadBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlug'
type ApiOrgRepository_ReadBySlug_Call struct {
	*mock.Call
}

// ReadBySlug is a helper method to define mock.On call
//   - slugOrId string
func (_e *ApiOrgRepository_Expecter) ReadBySlug(slugOrId interface{}) *ApiOrgRepository_ReadBySlug_Call {
	return &ApiOrgRepository_ReadBySlug_Call{Call: _e.mock.On("ReadBySlug", slugOrId)}
}

func (_c *ApiOrgRepository_ReadBySlug_Call) Run(run func(slugOrId string)) *ApiOrgRepository_ReadBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *ApiOrgRepository_ReadBySlug_Call) Return(_a0 models.Org, _a1 error) *ApiOrgRepository_ReadBySlug_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ApiOrgRepository_ReadBySlug_Call) RunAndReturn(run func(string) (models.Org, error)) *ApiOrgRepository_ReadBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// NewApiOrgRepository creates a new instance of ApiOrgRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewApiOrgRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ApiOrgRepository {
	mock := &ApiOrgRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
