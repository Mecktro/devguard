// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	time "time"

	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// CoreAssetRiskHistoryRepository is an autogenerated mock type for the AssetRiskHistoryRepository type
type CoreAssetRiskHistoryRepository struct {
	mock.Mock
}

type CoreAssetRiskHistoryRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreAssetRiskHistoryRepository) EXPECT() *CoreAssetRiskHistoryRepository_Expecter {
	return &CoreAssetRiskHistoryRepository_Expecter{mock: &_m.Mock}
}

// GetRiskHistory provides a mock function with given fields: assetVersionName, assetID, start, end
func (_m *CoreAssetRiskHistoryRepository) GetRiskHistory(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error) {
	ret := _m.Called(assetVersionName, assetID, start, end)

	if len(ret) == 0 {
		panic("no return value specified for GetRiskHistory")
	}

	var r0 []models.AssetRiskHistory
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, time.Time, time.Time) ([]models.AssetRiskHistory, error)); ok {
		return rf(assetVersionName, assetID, start, end)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, time.Time, time.Time) []models.AssetRiskHistory); ok {
		r0 = rf(assetVersionName, assetID, start, end)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetRiskHistory)
		}
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, time.Time, time.Time) error); ok {
		r1 = rf(assetVersionName, assetID, start, end)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetRiskHistoryRepository_GetRiskHistory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRiskHistory'
type CoreAssetRiskHistoryRepository_GetRiskHistory_Call struct {
	*mock.Call
}

// GetRiskHistory is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - start time.Time
//   - end time.Time
func (_e *CoreAssetRiskHistoryRepository_Expecter) GetRiskHistory(assetVersionName interface{}, assetID interface{}, start interface{}, end interface{}) *CoreAssetRiskHistoryRepository_GetRiskHistory_Call {
	return &CoreAssetRiskHistoryRepository_GetRiskHistory_Call{Call: _e.mock.On("GetRiskHistory", assetVersionName, assetID, start, end)}
}

func (_c *CoreAssetRiskHistoryRepository_GetRiskHistory_Call) Run(run func(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time)) *CoreAssetRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(time.Time), args[3].(time.Time))
	})
	return _c
}

func (_c *CoreAssetRiskHistoryRepository_GetRiskHistory_Call) Return(_a0 []models.AssetRiskHistory, _a1 error) *CoreAssetRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetRiskHistoryRepository_GetRiskHistory_Call) RunAndReturn(run func(string, uuid.UUID, time.Time, time.Time) ([]models.AssetRiskHistory, error)) *CoreAssetRiskHistoryRepository_GetRiskHistory_Call {
	_c.Call.Return(run)
	return _c
}

// GetRiskHistoryByProject provides a mock function with given fields: projectId, day
func (_m *CoreAssetRiskHistoryRepository) GetRiskHistoryByProject(projectId uuid.UUID, day time.Time) ([]models.AssetRiskHistory, error) {
	ret := _m.Called(projectId, day)

	if len(ret) == 0 {
		panic("no return value specified for GetRiskHistoryByProject")
	}

	var r0 []models.AssetRiskHistory
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time) ([]models.AssetRiskHistory, error)); ok {
		return rf(projectId, day)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time) []models.AssetRiskHistory); ok {
		r0 = rf(projectId, day)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetRiskHistory)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, time.Time) error); ok {
		r1 = rf(projectId, day)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetRiskHistoryByProject'
type CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call struct {
	*mock.Call
}

// GetRiskHistoryByProject is a helper method to define mock.On call
//   - projectId uuid.UUID
//   - day time.Time
func (_e *CoreAssetRiskHistoryRepository_Expecter) GetRiskHistoryByProject(projectId interface{}, day interface{}) *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	return &CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call{Call: _e.mock.On("GetRiskHistoryByProject", projectId, day)}
}

func (_c *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call) Run(run func(projectId uuid.UUID, day time.Time)) *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(time.Time))
	})
	return _c
}

func (_c *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call) Return(_a0 []models.AssetRiskHistory, _a1 error) *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call) RunAndReturn(run func(uuid.UUID, time.Time) ([]models.AssetRiskHistory, error)) *CoreAssetRiskHistoryRepository_GetRiskHistoryByProject_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateRiskAggregation provides a mock function with given fields: assetRisk
func (_m *CoreAssetRiskHistoryRepository) UpdateRiskAggregation(assetRisk *models.AssetRiskHistory) error {
	ret := _m.Called(assetRisk)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRiskAggregation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*models.AssetRiskHistory) error); ok {
		r0 = rf(assetRisk)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateRiskAggregation'
type CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call struct {
	*mock.Call
}

// UpdateRiskAggregation is a helper method to define mock.On call
//   - assetRisk *models.AssetRiskHistory
func (_e *CoreAssetRiskHistoryRepository_Expecter) UpdateRiskAggregation(assetRisk interface{}) *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	return &CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call{Call: _e.mock.On("UpdateRiskAggregation", assetRisk)}
}

func (_c *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call) Run(run func(assetRisk *models.AssetRiskHistory)) *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*models.AssetRiskHistory))
	})
	return _c
}

func (_c *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call) Return(_a0 error) *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call) RunAndReturn(run func(*models.AssetRiskHistory) error) *CoreAssetRiskHistoryRepository_UpdateRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreAssetRiskHistoryRepository creates a new instance of CoreAssetRiskHistoryRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreAssetRiskHistoryRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreAssetRiskHistoryRepository {
	mock := &CoreAssetRiskHistoryRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
