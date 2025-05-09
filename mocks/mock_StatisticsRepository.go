// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	time "time"

	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// StatisticsRepository is an autogenerated mock type for the StatisticsRepository type
type StatisticsRepository struct {
	mock.Mock
}

type StatisticsRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsRepository) EXPECT() *StatisticsRepository_Expecter {
	return &StatisticsRepository_Expecter{mock: &_m.Mock}
}

// AverageFixingTime provides a mock function with given fields: assetVersionName, assetID, riskIntervalStart, riskIntervalEnd
func (_m *StatisticsRepository) AverageFixingTime(assetVersionName string, assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64) (time.Duration, error) {
	ret := _m.Called(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)

	if len(ret) == 0 {
		panic("no return value specified for AverageFixingTime")
	}

	var r0 time.Duration
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, float64, float64) (time.Duration, error)); ok {
		return rf(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, float64, float64) time.Duration); ok {
		r0 = rf(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, float64, float64) error); ok {
		r1 = rf(assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsRepository_AverageFixingTime_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AverageFixingTime'
type StatisticsRepository_AverageFixingTime_Call struct {
	*mock.Call
}

// AverageFixingTime is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - riskIntervalStart float64
//   - riskIntervalEnd float64
func (_e *StatisticsRepository_Expecter) AverageFixingTime(assetVersionName interface{}, assetID interface{}, riskIntervalStart interface{}, riskIntervalEnd interface{}) *StatisticsRepository_AverageFixingTime_Call {
	return &StatisticsRepository_AverageFixingTime_Call{Call: _e.mock.On("AverageFixingTime", assetVersionName, assetID, riskIntervalStart, riskIntervalEnd)}
}

func (_c *StatisticsRepository_AverageFixingTime_Call) Run(run func(assetVersionName string, assetID uuid.UUID, riskIntervalStart float64, riskIntervalEnd float64)) *StatisticsRepository_AverageFixingTime_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(float64), args[3].(float64))
	})
	return _c
}

func (_c *StatisticsRepository_AverageFixingTime_Call) Return(_a0 time.Duration, _a1 error) *StatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsRepository_AverageFixingTime_Call) RunAndReturn(run func(string, uuid.UUID, float64, float64) (time.Duration, error)) *StatisticsRepository_AverageFixingTime_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetCvssDistribution provides a mock function with given fields: assetVersionName, assetID, assetName
func (_m *StatisticsRepository) GetAssetCvssDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _m.Called(assetVersionName, assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetCvssDistribution")
	}

	var r0 models.AssetRiskDistribution
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) (models.AssetRiskDistribution, error)); ok {
		return rf(assetVersionName, assetID, assetName)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) models.AssetRiskDistribution); ok {
		r0 = rf(assetVersionName, assetID, assetName)
	} else {
		r0 = ret.Get(0).(models.AssetRiskDistribution)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, string) error); ok {
		r1 = rf(assetVersionName, assetID, assetName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsRepository_GetAssetCvssDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetCvssDistribution'
type StatisticsRepository_GetAssetCvssDistribution_Call struct {
	*mock.Call
}

// GetAssetCvssDistribution is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsRepository_Expecter) GetAssetCvssDistribution(assetVersionName interface{}, assetID interface{}, assetName interface{}) *StatisticsRepository_GetAssetCvssDistribution_Call {
	return &StatisticsRepository_GetAssetCvssDistribution_Call{Call: _e.mock.On("GetAssetCvssDistribution", assetVersionName, assetID, assetName)}
}

func (_c *StatisticsRepository_GetAssetCvssDistribution_Call) Run(run func(assetVersionName string, assetID uuid.UUID, assetName string)) *StatisticsRepository_GetAssetCvssDistribution_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string))
	})
	return _c
}

func (_c *StatisticsRepository_GetAssetCvssDistribution_Call) Return(_a0 models.AssetRiskDistribution, _a1 error) *StatisticsRepository_GetAssetCvssDistribution_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsRepository_GetAssetCvssDistribution_Call) RunAndReturn(run func(string, uuid.UUID, string) (models.AssetRiskDistribution, error)) *StatisticsRepository_GetAssetCvssDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetRiskDistribution provides a mock function with given fields: assetVersionName, assetID, assetName
func (_m *StatisticsRepository) GetAssetRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _m.Called(assetVersionName, assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetRiskDistribution")
	}

	var r0 models.AssetRiskDistribution
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) (models.AssetRiskDistribution, error)); ok {
		return rf(assetVersionName, assetID, assetName)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) models.AssetRiskDistribution); ok {
		r0 = rf(assetVersionName, assetID, assetName)
	} else {
		r0 = ret.Get(0).(models.AssetRiskDistribution)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, string) error); ok {
		r1 = rf(assetVersionName, assetID, assetName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsRepository_GetAssetRiskDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetRiskDistribution'
type StatisticsRepository_GetAssetRiskDistribution_Call struct {
	*mock.Call
}

// GetAssetRiskDistribution is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsRepository_Expecter) GetAssetRiskDistribution(assetVersionName interface{}, assetID interface{}, assetName interface{}) *StatisticsRepository_GetAssetRiskDistribution_Call {
	return &StatisticsRepository_GetAssetRiskDistribution_Call{Call: _e.mock.On("GetAssetRiskDistribution", assetVersionName, assetID, assetName)}
}

func (_c *StatisticsRepository_GetAssetRiskDistribution_Call) Run(run func(assetVersionName string, assetID uuid.UUID, assetName string)) *StatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string))
	})
	return _c
}

func (_c *StatisticsRepository_GetAssetRiskDistribution_Call) Return(_a0 models.AssetRiskDistribution, _a1 error) *StatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsRepository_GetAssetRiskDistribution_Call) RunAndReturn(run func(string, uuid.UUID, string) (models.AssetRiskDistribution, error)) *StatisticsRepository_GetAssetRiskDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnCountByScannerId provides a mock function with given fields: assetVersionName, assetID
func (_m *StatisticsRepository) GetDependencyVulnCountByScannerId(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	ret := _m.Called(assetVersionName, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnCountByScannerId")
	}

	var r0 map[string]int
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) (map[string]int, error)); ok {
		return rf(assetVersionName, assetID)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) map[string]int); ok {
		r0 = rf(assetVersionName, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]int)
		}
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID) error); ok {
		r1 = rf(assetVersionName, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsRepository_GetDependencyVulnCountByScannerId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnCountByScannerId'
type StatisticsRepository_GetDependencyVulnCountByScannerId_Call struct {
	*mock.Call
}

// GetDependencyVulnCountByScannerId is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *StatisticsRepository_Expecter) GetDependencyVulnCountByScannerId(assetVersionName interface{}, assetID interface{}) *StatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	return &StatisticsRepository_GetDependencyVulnCountByScannerId_Call{Call: _e.mock.On("GetDependencyVulnCountByScannerId", assetVersionName, assetID)}
}

func (_c *StatisticsRepository_GetDependencyVulnCountByScannerId_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *StatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsRepository_GetDependencyVulnCountByScannerId_Call) Return(_a0 map[string]int, _a1 error) *StatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsRepository_GetDependencyVulnCountByScannerId_Call) RunAndReturn(run func(string, uuid.UUID) (map[string]int, error)) *StatisticsRepository_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Return(run)
	return _c
}

// TimeTravelDependencyVulnState provides a mock function with given fields: assetVersionName, assetID, _a2
func (_m *StatisticsRepository) TimeTravelDependencyVulnState(assetVersionName string, assetID uuid.UUID, _a2 time.Time) ([]models.DependencyVuln, error) {
	ret := _m.Called(assetVersionName, assetID, _a2)

	if len(ret) == 0 {
		panic("no return value specified for TimeTravelDependencyVulnState")
	}

	var r0 []models.DependencyVuln
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, time.Time) ([]models.DependencyVuln, error)); ok {
		return rf(assetVersionName, assetID, _a2)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, time.Time) []models.DependencyVuln); ok {
		r0 = rf(assetVersionName, assetID, _a2)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVuln)
		}
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, time.Time) error); ok {
		r1 = rf(assetVersionName, assetID, _a2)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsRepository_TimeTravelDependencyVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TimeTravelDependencyVulnState'
type StatisticsRepository_TimeTravelDependencyVulnState_Call struct {
	*mock.Call
}

// TimeTravelDependencyVulnState is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - _a2 time.Time
func (_e *StatisticsRepository_Expecter) TimeTravelDependencyVulnState(assetVersionName interface{}, assetID interface{}, _a2 interface{}) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	return &StatisticsRepository_TimeTravelDependencyVulnState_Call{Call: _e.mock.On("TimeTravelDependencyVulnState", assetVersionName, assetID, _a2)}
}

func (_c *StatisticsRepository_TimeTravelDependencyVulnState_Call) Run(run func(assetVersionName string, assetID uuid.UUID, _a2 time.Time)) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(time.Time))
	})
	return _c
}

func (_c *StatisticsRepository_TimeTravelDependencyVulnState_Call) Return(_a0 []models.DependencyVuln, _a1 error) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsRepository_TimeTravelDependencyVulnState_Call) RunAndReturn(run func(string, uuid.UUID, time.Time) ([]models.DependencyVuln, error)) *StatisticsRepository_TimeTravelDependencyVulnState_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsRepository creates a new instance of StatisticsRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsRepository {
	mock := &StatisticsRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
