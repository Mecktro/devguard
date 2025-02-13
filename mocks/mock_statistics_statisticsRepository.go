// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	time "time"

	uuid "github.com/google/uuid"
)

// StatisticsStatisticsRepository is an autogenerated mock type for the statisticsRepository type
type StatisticsStatisticsRepository struct {
	mock.Mock
}

type StatisticsStatisticsRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsStatisticsRepository) EXPECT() *StatisticsStatisticsRepository_Expecter {
	return &StatisticsStatisticsRepository_Expecter{mock: &_m.Mock}
}

// AverageFixingTime provides a mock function with given fields: assetID, riskIntervalStart, riskIntervalEnd
func (_m *StatisticsStatisticsRepository) AverageFixingTime(assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64) (time.Duration, error) {
	ret := _m.Called(assetID, riskIntervalStart, riskIntervalEnd)

	if len(ret) == 0 {
		panic("no return value specified for AverageFixingTime")
	}

	var r0 time.Duration
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, float64, float64) (time.Duration, error)); ok {
		return rf(assetID, riskIntervalStart, riskIntervalEnd)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, float64, float64) time.Duration); ok {
		r0 = rf(assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, float64, float64) error); ok {
		r1 = rf(assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_AverageFixingTime_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AverageFixingTime'
type StatisticsStatisticsRepository_AverageFixingTime_Call struct {
	*mock.Call
}

// AverageFixingTime is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - riskIntervalStart float64
//   - riskIntervalEnd float64
func (_e *StatisticsStatisticsRepository_Expecter) AverageFixingTime(assetID interface{}, riskIntervalStart interface{}, riskIntervalEnd interface{}) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	return &StatisticsStatisticsRepository_AverageFixingTime_Call{Call: _e.mock.On("AverageFixingTime", assetID, riskIntervalStart, riskIntervalEnd)}
}

func (_c *StatisticsStatisticsRepository_AverageFixingTime_Call) Run(run func(assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64)) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(float64), args[2].(float64))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_AverageFixingTime_Call) Return(_a0 time.Duration, _a1 error) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_AverageFixingTime_Call) RunAndReturn(run func(uuid.UUID, float64, float64) (time.Duration, error)) *StatisticsStatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetRiskDistribution provides a mock function with given fields: assetID, assetName
func (_m *StatisticsStatisticsRepository) GetAssetRiskDistribution(assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _m.Called(assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetRiskDistribution")
	}

	var r0 models.AssetRiskDistribution
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) (models.AssetRiskDistribution, error)); ok {
		return rf(assetID, assetName)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) models.AssetRiskDistribution); ok {
		r0 = rf(assetID, assetName)
	} else {
		r0 = ret.Get(0).(models.AssetRiskDistribution)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = rf(assetID, assetName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_GetAssetRiskDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetRiskDistribution'
type StatisticsStatisticsRepository_GetAssetRiskDistribution_Call struct {
	*mock.Call
}

// GetAssetRiskDistribution is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsStatisticsRepository_Expecter) GetAssetRiskDistribution(assetID interface{}, assetName interface{}) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	return &StatisticsStatisticsRepository_GetAssetRiskDistribution_Call{Call: _e.mock.On("GetAssetRiskDistribution", assetID, assetName)}
}

func (_c *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call) Run(run func(assetID uuid.UUID, assetName string)) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(string))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call) Return(_a0 models.AssetRiskDistribution, _a1 error) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call) RunAndReturn(run func(uuid.UUID, string) (models.AssetRiskDistribution, error)) *StatisticsStatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetFlawCountByScannerId provides a mock function with given fields: assetID
func (_m *StatisticsStatisticsRepository) GetFlawCountByScannerId(assetID uuid.UUID) (map[string]int, error) {
	ret := _m.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetFlawCountByScannerId")
	}

	var r0 map[string]int
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (map[string]int, error)); ok {
		return rf(assetID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) map[string]int); ok {
		r0 = rf(assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]int)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_GetFlawCountByScannerId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFlawCountByScannerId'
type StatisticsStatisticsRepository_GetFlawCountByScannerId_Call struct {
	*mock.Call
}

// GetFlawCountByScannerId is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *StatisticsStatisticsRepository_Expecter) GetFlawCountByScannerId(assetID interface{}) *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call {
	return &StatisticsStatisticsRepository_GetFlawCountByScannerId_Call{Call: _e.mock.On("GetFlawCountByScannerId", assetID)}
}

func (_c *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call) Run(run func(assetID uuid.UUID)) *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call) Return(_a0 map[string]int, _a1 error) *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call) RunAndReturn(run func(uuid.UUID) (map[string]int, error)) *StatisticsStatisticsRepository_GetFlawCountByScannerId_Call {
	_c.Call.Return(run)
	return _c
}

// TimeTravelFlawState provides a mock function with given fields: assetID, _a1
func (_m *StatisticsStatisticsRepository) TimeTravelFlawState(assetID uuid.UUID, _a1 time.Time) ([]models.Flaw, error) {
	ret := _m.Called(assetID, _a1)

	if len(ret) == 0 {
		panic("no return value specified for TimeTravelFlawState")
	}

	var r0 []models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time) ([]models.Flaw, error)); ok {
		return rf(assetID, _a1)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time) []models.Flaw); ok {
		r0 = rf(assetID, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Flaw)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, time.Time) error); ok {
		r1 = rf(assetID, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsRepository_TimeTravelFlawState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TimeTravelFlawState'
type StatisticsStatisticsRepository_TimeTravelFlawState_Call struct {
	*mock.Call
}

// TimeTravelFlawState is a helper method to define mock.On call
//   - assetID uuid.UUID
//   - _a1 time.Time
func (_e *StatisticsStatisticsRepository_Expecter) TimeTravelFlawState(assetID interface{}, _a1 interface{}) *StatisticsStatisticsRepository_TimeTravelFlawState_Call {
	return &StatisticsStatisticsRepository_TimeTravelFlawState_Call{Call: _e.mock.On("TimeTravelFlawState", assetID, _a1)}
}

func (_c *StatisticsStatisticsRepository_TimeTravelFlawState_Call) Run(run func(assetID uuid.UUID, _a1 time.Time)) *StatisticsStatisticsRepository_TimeTravelFlawState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(time.Time))
	})
	return _c
}

func (_c *StatisticsStatisticsRepository_TimeTravelFlawState_Call) Return(_a0 []models.Flaw, _a1 error) *StatisticsStatisticsRepository_TimeTravelFlawState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsRepository_TimeTravelFlawState_Call) RunAndReturn(run func(uuid.UUID, time.Time) ([]models.Flaw, error)) *StatisticsStatisticsRepository_TimeTravelFlawState_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsStatisticsRepository creates a new instance of StatisticsStatisticsRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsStatisticsRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsStatisticsRepository {
	mock := &StatisticsStatisticsRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
