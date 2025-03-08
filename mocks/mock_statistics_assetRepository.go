// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// StatisticsAssetRepository is an autogenerated mock type for the assetRepository type
type StatisticsAssetRepository struct {
	mock.Mock
}

type StatisticsAssetRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsAssetRepository) EXPECT() *StatisticsAssetRepository_Expecter {
	return &StatisticsAssetRepository_Expecter{mock: &_m.Mock}
}

// GetByAssetID provides a mock function with given fields: assetID
func (_m *StatisticsAssetRepository) GetByAssetID(assetID uuid.UUID) (models.Asset, error) {
	ret := _m.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetByAssetID")
	}

	var r0 models.Asset
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.Asset, error)); ok {
		return rf(assetID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.Asset); ok {
		r0 = rf(assetID)
	} else {
		r0 = ret.Get(0).(models.Asset)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsAssetRepository_GetByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByAssetID'
type StatisticsAssetRepository_GetByAssetID_Call struct {
	*mock.Call
}

// GetByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *StatisticsAssetRepository_Expecter) GetByAssetID(assetID interface{}) *StatisticsAssetRepository_GetByAssetID_Call {
	return &StatisticsAssetRepository_GetByAssetID_Call{Call: _e.mock.On("GetByAssetID", assetID)}
}

func (_c *StatisticsAssetRepository_GetByAssetID_Call) Run(run func(assetID uuid.UUID)) *StatisticsAssetRepository_GetByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsAssetRepository_GetByAssetID_Call) Return(_a0 models.Asset, _a1 error) *StatisticsAssetRepository_GetByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsAssetRepository_GetByAssetID_Call) RunAndReturn(run func(uuid.UUID) (models.Asset, error)) *StatisticsAssetRepository_GetByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsAssetRepository creates a new instance of StatisticsAssetRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsAssetRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsAssetRepository {
	mock := &StatisticsAssetRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
