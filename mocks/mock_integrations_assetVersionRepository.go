// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	uuid "github.com/google/uuid"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// IntegrationsAssetVersionRepository is an autogenerated mock type for the assetVersionRepository type
type IntegrationsAssetVersionRepository struct {
	mock.Mock
}

type IntegrationsAssetVersionRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsAssetVersionRepository) EXPECT() *IntegrationsAssetVersionRepository_Expecter {
	return &IntegrationsAssetVersionRepository_Expecter{mock: &_m.Mock}
}

// Read provides a mock function with given fields: assetVersionName, assetID
func (_m *IntegrationsAssetVersionRepository) Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error) {
	ret := _m.Called(assetVersionName, assetID)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) (models.AssetVersion, error)); ok {
		return rf(assetVersionName, assetID)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) models.AssetVersion); ok {
		r0 = rf(assetVersionName, assetID)
	} else {
		r0 = ret.Get(0).(models.AssetVersion)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID) error); ok {
		r1 = rf(assetVersionName, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsAssetVersionRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type IntegrationsAssetVersionRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *IntegrationsAssetVersionRepository_Expecter) Read(assetVersionName interface{}, assetID interface{}) *IntegrationsAssetVersionRepository_Read_Call {
	return &IntegrationsAssetVersionRepository_Read_Call{Call: _e.mock.On("Read", assetVersionName, assetID)}
}

func (_c *IntegrationsAssetVersionRepository_Read_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *IntegrationsAssetVersionRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *IntegrationsAssetVersionRepository_Read_Call) Return(_a0 models.AssetVersion, _a1 error) *IntegrationsAssetVersionRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsAssetVersionRepository_Read_Call) RunAndReturn(run func(string, uuid.UUID) (models.AssetVersion, error)) *IntegrationsAssetVersionRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsAssetVersionRepository creates a new instance of IntegrationsAssetVersionRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsAssetVersionRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsAssetVersionRepository {
	mock := &IntegrationsAssetVersionRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
