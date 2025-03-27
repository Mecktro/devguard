// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	uuid "github.com/google/uuid"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// ApiAssetRepository is an autogenerated mock type for the assetRepository type
type ApiAssetRepository struct {
	mock.Mock
}

type ApiAssetRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ApiAssetRepository) EXPECT() *ApiAssetRepository_Expecter {
	return &ApiAssetRepository_Expecter{mock: &_m.Mock}
}

// ReadBySlug provides a mock function with given fields: projectID, slug
func (_m *ApiAssetRepository) ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error) {
	ret := _m.Called(projectID, slug)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlug")
	}

	var r0 models.Asset
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) (models.Asset, error)); ok {
		return rf(projectID, slug)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) models.Asset); ok {
		r0 = rf(projectID, slug)
	} else {
		r0 = ret.Get(0).(models.Asset)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = rf(projectID, slug)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ApiAssetRepository_ReadBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlug'
type ApiAssetRepository_ReadBySlug_Call struct {
	*mock.Call
}

// ReadBySlug is a helper method to define mock.On call
//   - projectID uuid.UUID
//   - slug string
func (_e *ApiAssetRepository_Expecter) ReadBySlug(projectID interface{}, slug interface{}) *ApiAssetRepository_ReadBySlug_Call {
	return &ApiAssetRepository_ReadBySlug_Call{Call: _e.mock.On("ReadBySlug", projectID, slug)}
}

func (_c *ApiAssetRepository_ReadBySlug_Call) Run(run func(projectID uuid.UUID, slug string)) *ApiAssetRepository_ReadBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(string))
	})
	return _c
}

func (_c *ApiAssetRepository_ReadBySlug_Call) Return(_a0 models.Asset, _a1 error) *ApiAssetRepository_ReadBySlug_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ApiAssetRepository_ReadBySlug_Call) RunAndReturn(run func(uuid.UUID, string) (models.Asset, error)) *ApiAssetRepository_ReadBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// NewApiAssetRepository creates a new instance of ApiAssetRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewApiAssetRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ApiAssetRepository {
	mock := &ApiAssetRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
