// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	statistics "github.com/l3montree-dev/devguard/internal/core/statistics"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	time "time"

	uuid "github.com/google/uuid"
)

// StatisticsStatisticsService is an autogenerated mock type for the statisticsService type
type StatisticsStatisticsService struct {
	mock.Mock
}

type StatisticsStatisticsService_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsStatisticsService) EXPECT() *StatisticsStatisticsService_Expecter {
	return &StatisticsStatisticsService_Expecter{mock: &_m.Mock}
}

// GetAssetVersionRiskDistribution provides a mock function with given fields: assetVersionName, assetID, assetName
func (_m *StatisticsStatisticsService) GetAssetVersionRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	ret := _m.Called(assetVersionName, assetID, assetName)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetVersionRiskDistribution")
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

// StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetVersionRiskDistribution'
type StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call struct {
	*mock.Call
}

// GetAssetVersionRiskDistribution is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - assetName string
func (_e *StatisticsStatisticsService_Expecter) GetAssetVersionRiskDistribution(assetVersionName interface{}, assetID interface{}, assetName interface{}) *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call {
	return &StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call{Call: _e.mock.On("GetAssetVersionRiskDistribution", assetVersionName, assetID, assetName)}
}

func (_c *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call) Run(run func(assetVersionName string, assetID uuid.UUID, assetName string)) *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call) Return(_a0 models.AssetRiskDistribution, _a1 error) *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call) RunAndReturn(run func(string, uuid.UUID, string) (models.AssetRiskDistribution, error)) *StatisticsStatisticsService_GetAssetVersionRiskDistribution_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetVersionRiskHistory provides a mock function with given fields: assetVersionName, assetID, start, end
func (_m *StatisticsStatisticsService) GetAssetVersionRiskHistory(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time) ([]models.AssetRiskHistory, error) {
	ret := _m.Called(assetVersionName, assetID, start, end)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetVersionRiskHistory")
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

// StatisticsStatisticsService_GetAssetVersionRiskHistory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetVersionRiskHistory'
type StatisticsStatisticsService_GetAssetVersionRiskHistory_Call struct {
	*mock.Call
}

// GetAssetVersionRiskHistory is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - start time.Time
//   - end time.Time
func (_e *StatisticsStatisticsService_Expecter) GetAssetVersionRiskHistory(assetVersionName interface{}, assetID interface{}, start interface{}, end interface{}) *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call {
	return &StatisticsStatisticsService_GetAssetVersionRiskHistory_Call{Call: _e.mock.On("GetAssetVersionRiskHistory", assetVersionName, assetID, start, end)}
}

func (_c *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call) Run(run func(assetVersionName string, assetID uuid.UUID, start time.Time, end time.Time)) *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(time.Time), args[3].(time.Time))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call) Return(_a0 []models.AssetRiskHistory, _a1 error) *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call) RunAndReturn(run func(string, uuid.UUID, time.Time, time.Time) ([]models.AssetRiskHistory, error)) *StatisticsStatisticsService_GetAssetVersionRiskHistory_Call {
	_c.Call.Return(run)
	return _c
}

// GetAverageFixingTime provides a mock function with given fields: assetVersionName, assetID, severity
func (_m *StatisticsStatisticsService) GetAverageFixingTime(assetVersionName string, assetID uuid.UUID, severity string) (time.Duration, error) {
	ret := _m.Called(assetVersionName, assetID, severity)

	if len(ret) == 0 {
		panic("no return value specified for GetAverageFixingTime")
	}

	var r0 time.Duration
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) (time.Duration, error)); ok {
		return rf(assetVersionName, assetID, severity)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) time.Duration); ok {
		r0 = rf(assetVersionName, assetID, severity)
	} else {
		r0 = ret.Get(0).(time.Duration)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, string) error); ok {
		r1 = rf(assetVersionName, assetID, severity)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsService_GetAverageFixingTime_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAverageFixingTime'
type StatisticsStatisticsService_GetAverageFixingTime_Call struct {
	*mock.Call
}

// GetAverageFixingTime is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - severity string
func (_e *StatisticsStatisticsService_Expecter) GetAverageFixingTime(assetVersionName interface{}, assetID interface{}, severity interface{}) *StatisticsStatisticsService_GetAverageFixingTime_Call {
	return &StatisticsStatisticsService_GetAverageFixingTime_Call{Call: _e.mock.On("GetAverageFixingTime", assetVersionName, assetID, severity)}
}

func (_c *StatisticsStatisticsService_GetAverageFixingTime_Call) Run(run func(assetVersionName string, assetID uuid.UUID, severity string)) *StatisticsStatisticsService_GetAverageFixingTime_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetAverageFixingTime_Call) Return(_a0 time.Duration, _a1 error) *StatisticsStatisticsService_GetAverageFixingTime_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetAverageFixingTime_Call) RunAndReturn(run func(string, uuid.UUID, string) (time.Duration, error)) *StatisticsStatisticsService_GetAverageFixingTime_Call {
	_c.Call.Return(run)
	return _c
}

// GetComponentRisk provides a mock function with given fields: assetVersionName, assetID
func (_m *StatisticsStatisticsService) GetComponentRisk(assetVersionName string, assetID uuid.UUID) (map[string]float64, error) {
	ret := _m.Called(assetVersionName, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetComponentRisk")
	}

	var r0 map[string]float64
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) (map[string]float64, error)); ok {
		return rf(assetVersionName, assetID)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) map[string]float64); ok {
		r0 = rf(assetVersionName, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]float64)
		}
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID) error); ok {
		r1 = rf(assetVersionName, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsService_GetComponentRisk_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetComponentRisk'
type StatisticsStatisticsService_GetComponentRisk_Call struct {
	*mock.Call
}

// GetComponentRisk is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *StatisticsStatisticsService_Expecter) GetComponentRisk(assetVersionName interface{}, assetID interface{}) *StatisticsStatisticsService_GetComponentRisk_Call {
	return &StatisticsStatisticsService_GetComponentRisk_Call{Call: _e.mock.On("GetComponentRisk", assetVersionName, assetID)}
}

func (_c *StatisticsStatisticsService_GetComponentRisk_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *StatisticsStatisticsService_GetComponentRisk_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetComponentRisk_Call) Return(_a0 map[string]float64, _a1 error) *StatisticsStatisticsService_GetComponentRisk_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetComponentRisk_Call) RunAndReturn(run func(string, uuid.UUID) (map[string]float64, error)) *StatisticsStatisticsService_GetComponentRisk_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyCountPerscanner provides a mock function with given fields: assetVersionName, assetID
func (_m *StatisticsStatisticsService) GetDependencyCountPerscanner(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	ret := _m.Called(assetVersionName, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyCountPerscanner")
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

// StatisticsStatisticsService_GetDependencyCountPerscanner_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyCountPerscanner'
type StatisticsStatisticsService_GetDependencyCountPerscanner_Call struct {
	*mock.Call
}

// GetDependencyCountPerscanner is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *StatisticsStatisticsService_Expecter) GetDependencyCountPerscanner(assetVersionName interface{}, assetID interface{}) *StatisticsStatisticsService_GetDependencyCountPerscanner_Call {
	return &StatisticsStatisticsService_GetDependencyCountPerscanner_Call{Call: _e.mock.On("GetDependencyCountPerscanner", assetVersionName, assetID)}
}

func (_c *StatisticsStatisticsService_GetDependencyCountPerscanner_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *StatisticsStatisticsService_GetDependencyCountPerscanner_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetDependencyCountPerscanner_Call) Return(_a0 map[string]int, _a1 error) *StatisticsStatisticsService_GetDependencyCountPerscanner_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetDependencyCountPerscanner_Call) RunAndReturn(run func(string, uuid.UUID) (map[string]int, error)) *StatisticsStatisticsService_GetDependencyCountPerscanner_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnAggregationStateAndChangeSince provides a mock function with given fields: assetVersionName, assetID, calculateChangeTo
func (_m *StatisticsStatisticsService) GetDependencyVulnAggregationStateAndChangeSince(assetVersionName string, assetID uuid.UUID, calculateChangeTo time.Time) (statistics.DependencyVulnAggregationStateAndChange, error) {
	ret := _m.Called(assetVersionName, assetID, calculateChangeTo)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnAggregationStateAndChangeSince")
	}

	var r0 statistics.DependencyVulnAggregationStateAndChange
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, time.Time) (statistics.DependencyVulnAggregationStateAndChange, error)); ok {
		return rf(assetVersionName, assetID, calculateChangeTo)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, time.Time) statistics.DependencyVulnAggregationStateAndChange); ok {
		r0 = rf(assetVersionName, assetID, calculateChangeTo)
	} else {
		r0 = ret.Get(0).(statistics.DependencyVulnAggregationStateAndChange)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, time.Time) error); ok {
		r1 = rf(assetVersionName, assetID, calculateChangeTo)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnAggregationStateAndChangeSince'
type StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call struct {
	*mock.Call
}

// GetDependencyVulnAggregationStateAndChangeSince is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - calculateChangeTo time.Time
func (_e *StatisticsStatisticsService_Expecter) GetDependencyVulnAggregationStateAndChangeSince(assetVersionName interface{}, assetID interface{}, calculateChangeTo interface{}) *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call {
	return &StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call{Call: _e.mock.On("GetDependencyVulnAggregationStateAndChangeSince", assetVersionName, assetID, calculateChangeTo)}
}

func (_c *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call) Run(run func(assetVersionName string, assetID uuid.UUID, calculateChangeTo time.Time)) *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(time.Time))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call) Return(_a0 statistics.DependencyVulnAggregationStateAndChange, _a1 error) *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call) RunAndReturn(run func(string, uuid.UUID, time.Time) (statistics.DependencyVulnAggregationStateAndChange, error)) *StatisticsStatisticsService_GetDependencyVulnAggregationStateAndChangeSince_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnCountByScannerId provides a mock function with given fields: assetVersionName, assetID
func (_m *StatisticsStatisticsService) GetDependencyVulnCountByScannerId(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
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

// StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnCountByScannerId'
type StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call struct {
	*mock.Call
}

// GetDependencyVulnCountByScannerId is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *StatisticsStatisticsService_Expecter) GetDependencyVulnCountByScannerId(assetVersionName interface{}, assetID interface{}) *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call {
	return &StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call{Call: _e.mock.On("GetDependencyVulnCountByScannerId", assetVersionName, assetID)}
}

func (_c *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call) Return(_a0 map[string]int, _a1 error) *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call) RunAndReturn(run func(string, uuid.UUID) (map[string]int, error)) *StatisticsStatisticsService_GetDependencyVulnCountByScannerId_Call {
	_c.Call.Return(run)
	return _c
}

// GetProjectRiskHistory provides a mock function with given fields: projectID, start, end
func (_m *StatisticsStatisticsService) GetProjectRiskHistory(projectID uuid.UUID, start time.Time, end time.Time) ([]models.ProjectRiskHistory, error) {
	ret := _m.Called(projectID, start, end)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectRiskHistory")
	}

	var r0 []models.ProjectRiskHistory
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time) ([]models.ProjectRiskHistory, error)); ok {
		return rf(projectID, start, end)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, time.Time, time.Time) []models.ProjectRiskHistory); ok {
		r0 = rf(projectID, start, end)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ProjectRiskHistory)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, time.Time, time.Time) error); ok {
		r1 = rf(projectID, start, end)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsStatisticsService_GetProjectRiskHistory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjectRiskHistory'
type StatisticsStatisticsService_GetProjectRiskHistory_Call struct {
	*mock.Call
}

// GetProjectRiskHistory is a helper method to define mock.On call
//   - projectID uuid.UUID
//   - start time.Time
//   - end time.Time
func (_e *StatisticsStatisticsService_Expecter) GetProjectRiskHistory(projectID interface{}, start interface{}, end interface{}) *StatisticsStatisticsService_GetProjectRiskHistory_Call {
	return &StatisticsStatisticsService_GetProjectRiskHistory_Call{Call: _e.mock.On("GetProjectRiskHistory", projectID, start, end)}
}

func (_c *StatisticsStatisticsService_GetProjectRiskHistory_Call) Run(run func(projectID uuid.UUID, start time.Time, end time.Time)) *StatisticsStatisticsService_GetProjectRiskHistory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(time.Time), args[2].(time.Time))
	})
	return _c
}

func (_c *StatisticsStatisticsService_GetProjectRiskHistory_Call) Return(_a0 []models.ProjectRiskHistory, _a1 error) *StatisticsStatisticsService_GetProjectRiskHistory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsStatisticsService_GetProjectRiskHistory_Call) RunAndReturn(run func(uuid.UUID, time.Time, time.Time) ([]models.ProjectRiskHistory, error)) *StatisticsStatisticsService_GetProjectRiskHistory_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateAssetRiskAggregation provides a mock function with given fields: assetVersion, assetID, start, end, updateProject
func (_m *StatisticsStatisticsService) UpdateAssetRiskAggregation(assetVersion *models.AssetVersion, assetID uuid.UUID, start time.Time, end time.Time, updateProject bool) error {
	ret := _m.Called(assetVersion, assetID, start, end, updateProject)

	if len(ret) == 0 {
		panic("no return value specified for UpdateAssetRiskAggregation")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*models.AssetVersion, uuid.UUID, time.Time, time.Time, bool) error); ok {
		r0 = rf(assetVersion, assetID, start, end, updateProject)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StatisticsStatisticsService_UpdateAssetRiskAggregation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateAssetRiskAggregation'
type StatisticsStatisticsService_UpdateAssetRiskAggregation_Call struct {
	*mock.Call
}

// UpdateAssetRiskAggregation is a helper method to define mock.On call
//   - assetVersion *models.AssetVersion
//   - assetID uuid.UUID
//   - start time.Time
//   - end time.Time
//   - updateProject bool
func (_e *StatisticsStatisticsService_Expecter) UpdateAssetRiskAggregation(assetVersion interface{}, assetID interface{}, start interface{}, end interface{}, updateProject interface{}) *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call {
	return &StatisticsStatisticsService_UpdateAssetRiskAggregation_Call{Call: _e.mock.On("UpdateAssetRiskAggregation", assetVersion, assetID, start, end, updateProject)}
}

func (_c *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call) Run(run func(assetVersion *models.AssetVersion, assetID uuid.UUID, start time.Time, end time.Time, updateProject bool)) *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*models.AssetVersion), args[1].(uuid.UUID), args[2].(time.Time), args[3].(time.Time), args[4].(bool))
	})
	return _c
}

func (_c *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call) Return(_a0 error) *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call) RunAndReturn(run func(*models.AssetVersion, uuid.UUID, time.Time, time.Time, bool) error) *StatisticsStatisticsService_UpdateAssetRiskAggregation_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsStatisticsService creates a new instance of StatisticsStatisticsService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsStatisticsService(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsStatisticsService {
	mock := &StatisticsStatisticsService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
