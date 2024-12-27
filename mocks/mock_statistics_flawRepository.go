// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// StatisticsFlawRepository is an autogenerated mock type for the flawRepository type
type StatisticsFlawRepository struct {
	mock.Mock
}

type StatisticsFlawRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsFlawRepository) EXPECT() *StatisticsFlawRepository_Expecter {
	return &StatisticsFlawRepository_Expecter{mock: &_m.Mock}
}

// GetAllFlawsByAssetID provides a mock function with given fields: tx, assetID
func (_m *StatisticsFlawRepository) GetAllFlawsByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.Flaw, error) {
	ret := _m.Called(tx, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllFlawsByAssetID")
	}

	var r0 []models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) ([]models.Flaw, error)); ok {
		return rf(tx, assetID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) []models.Flaw); ok {
		r0 = rf(tx, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Flaw)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID) error); ok {
		r1 = rf(tx, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsFlawRepository_GetAllFlawsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllFlawsByAssetID'
type StatisticsFlawRepository_GetAllFlawsByAssetID_Call struct {
	*mock.Call
}

// GetAllFlawsByAssetID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
func (_e *StatisticsFlawRepository_Expecter) GetAllFlawsByAssetID(tx interface{}, assetID interface{}) *StatisticsFlawRepository_GetAllFlawsByAssetID_Call {
	return &StatisticsFlawRepository_GetAllFlawsByAssetID_Call{Call: _e.mock.On("GetAllFlawsByAssetID", tx, assetID)}
}

func (_c *StatisticsFlawRepository_GetAllFlawsByAssetID_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID)) *StatisticsFlawRepository_GetAllFlawsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsFlawRepository_GetAllFlawsByAssetID_Call) Return(_a0 []models.Flaw, _a1 error) *StatisticsFlawRepository_GetAllFlawsByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsFlawRepository_GetAllFlawsByAssetID_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.Flaw, error)) *StatisticsFlawRepository_GetAllFlawsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllOpenFlawsByAssetID provides a mock function with given fields: tx, assetID
func (_m *StatisticsFlawRepository) GetAllOpenFlawsByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.Flaw, error) {
	ret := _m.Called(tx, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllOpenFlawsByAssetID")
	}

	var r0 []models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) ([]models.Flaw, error)); ok {
		return rf(tx, assetID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) []models.Flaw); ok {
		r0 = rf(tx, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Flaw)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID) error); ok {
		r1 = rf(tx, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllOpenFlawsByAssetID'
type StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call struct {
	*mock.Call
}

// GetAllOpenFlawsByAssetID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
func (_e *StatisticsFlawRepository_Expecter) GetAllOpenFlawsByAssetID(tx interface{}, assetID interface{}) *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call {
	return &StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call{Call: _e.mock.On("GetAllOpenFlawsByAssetID", tx, assetID)}
}

func (_c *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID)) *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call) Return(_a0 []models.Flaw, _a1 error) *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.Flaw, error)) *StatisticsFlawRepository_GetAllOpenFlawsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsFlawRepository creates a new instance of StatisticsFlawRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsFlawRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsFlawRepository {
	mock := &StatisticsFlawRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
