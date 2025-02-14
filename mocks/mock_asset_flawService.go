// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// AssetDependencyVulnService is an autogenerated mock type for the dependencyVulnService type
type AssetDependencyVulnService struct {
	mock.Mock
}

type AssetDependencyVulnService_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetDependencyVulnService) EXPECT() *AssetDependencyVulnService_Expecter {
	return &AssetDependencyVulnService_Expecter{mock: &_m.Mock}
}

// RecalculateRawRiskAssessment provides a mock function with given fields: tx, userID, dependencyVulns, justification, _a4
func (_m *AssetDependencyVulnService) RecalculateRawRiskAssessment(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVulnerability, justification string, _a4 models.Asset) error {
	ret := _m.Called(tx, userID, dependencyVulns, justification, _a4)

	if len(ret) == 0 {
		panic("no return value specified for RecalculateRawRiskAssessment")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVulnerability, string, models.Asset) error); ok {
		r0 = rf(tx, userID, dependencyVulns, justification, _a4)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetDependencyVulnService_RecalculateRawRiskAssessment_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecalculateRawRiskAssessment'
type AssetDependencyVulnService_RecalculateRawRiskAssessment_Call struct {
	*mock.Call
}

// RecalculateRawRiskAssessment is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - justification string
//   - _a4 models.Asset
func (_e *AssetDependencyVulnService_Expecter) RecalculateRawRiskAssessment(tx interface{}, userID interface{}, dependencyVulns interface{}, justification interface{}, _a4 interface{}) *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call {
	return &AssetDependencyVulnService_RecalculateRawRiskAssessment_Call{Call: _e.mock.On("RecalculateRawRiskAssessment", tx, userID, dependencyVulns, justification, _a4)}
}

func (_c *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVulnerability, justification string, _a4 models.Asset)) *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVulnerability), args[3].(string), args[4].(models.Asset))
	})
	return _c
}

func (_c *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call) Return(_a0 error) *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVulnerability, string, models.Asset) error) *AssetDependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateDependencyVulnState provides a mock function with given fields: tx, userID, dependencyVuln, statusType, justification
func (_m *AssetDependencyVulnService) UpdateDependencyVulnState(tx *gorm.DB, userID string, dependencyVuln *models.DependencyVulnerability, statusType string, justification string) (models.DependencyVulnEvent, error) {
	ret := _m.Called(tx, userID, dependencyVuln, statusType, justification)

	if len(ret) == 0 {
		panic("no return value specified for UpdateDependencyVulnState")
	}

	var r0 models.DependencyVulnEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.DependencyVulnerability, string, string) (models.DependencyVulnEvent, error)); ok {
		return rf(tx, userID, dependencyVuln, statusType, justification)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.DependencyVulnerability, string, string) models.DependencyVulnEvent); ok {
		r0 = rf(tx, userID, dependencyVuln, statusType, justification)
	} else {
		r0 = ret.Get(0).(models.DependencyVulnEvent)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string, *models.DependencyVulnerability, string, string) error); ok {
		r1 = rf(tx, userID, dependencyVuln, statusType, justification)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetDependencyVulnService_UpdateDependencyVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateDependencyVulnState'
type AssetDependencyVulnService_UpdateDependencyVulnState_Call struct {
	*mock.Call
}

// UpdateDependencyVulnState is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVuln *models.DependencyVuln
//   - statusType string
//   - justification string
func (_e *AssetDependencyVulnService_Expecter) UpdateDependencyVulnState(tx interface{}, userID interface{}, dependencyVuln interface{}, statusType interface{}, justification interface{}) *AssetDependencyVulnService_UpdateDependencyVulnState_Call {
	return &AssetDependencyVulnService_UpdateDependencyVulnState_Call{Call: _e.mock.On("UpdateDependencyVulnState", tx, userID, dependencyVuln, statusType, justification)}
}

func (_c *AssetDependencyVulnService_UpdateDependencyVulnState_Call) Run(run func(tx *gorm.DB, userID string, dependencyVuln *models.DependencyVulnerability, statusType string, justification string)) *AssetDependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].(*models.DependencyVulnerability), args[3].(string), args[4].(string))
	})
	return _c
}

func (_c *AssetDependencyVulnService_UpdateDependencyVulnState_Call) Return(_a0 models.DependencyVulnEvent, _a1 error) *AssetDependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetDependencyVulnService_UpdateDependencyVulnState_Call) RunAndReturn(run func(*gorm.DB, string, *models.DependencyVulnerability, string, string) (models.DependencyVulnEvent, error)) *AssetDependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Return(run)
	return _c
}

// UserDetectedDependencyVulns provides a mock function with given fields: tx, userID, dependencyVulns, _a3, doRiskManagement
func (_m *AssetDependencyVulnService) UserDetectedDependencyVulns(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVulnerability, _a3 models.Asset, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, dependencyVulns, _a3, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserDetectedDependencyVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVulnerability, models.Asset, bool) error); ok {
		r0 = rf(tx, userID, dependencyVulns, _a3, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetDependencyVulnService_UserDetectedDependencyVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserDetectedDependencyVulns'
type AssetDependencyVulnService_UserDetectedDependencyVulns_Call struct {
	*mock.Call
}

// UserDetectedDependencyVulns is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - _a3 models.Asset
//   - doRiskManagement bool
func (_e *AssetDependencyVulnService_Expecter) UserDetectedDependencyVulns(tx interface{}, userID interface{}, dependencyVulns interface{}, _a3 interface{}, doRiskManagement interface{}) *AssetDependencyVulnService_UserDetectedDependencyVulns_Call {
	return &AssetDependencyVulnService_UserDetectedDependencyVulns_Call{Call: _e.mock.On("UserDetectedDependencyVulns", tx, userID, dependencyVulns, _a3, doRiskManagement)}
}

func (_c *AssetDependencyVulnService_UserDetectedDependencyVulns_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVulnerability, _a3 models.Asset, doRiskManagement bool)) *AssetDependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVulnerability), args[3].(models.Asset), args[4].(bool))
	})
	return _c
}

func (_c *AssetDependencyVulnService_UserDetectedDependencyVulns_Call) Return(_a0 error) *AssetDependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetDependencyVulnService_UserDetectedDependencyVulns_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVulnerability, models.Asset, bool) error) *AssetDependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Return(run)
	return _c
}

// UserFixedDependencyVulns provides a mock function with given fields: tx, userID, dependencyVulns, doRiskManagement
func (_m *AssetDependencyVulnService) UserFixedDependencyVulns(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVulnerability, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, dependencyVulns, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserFixedDependencyVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVulnerability, bool) error); ok {
		r0 = rf(tx, userID, dependencyVulns, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetDependencyVulnService_UserFixedDependencyVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserFixedDependencyVulns'
type AssetDependencyVulnService_UserFixedDependencyVulns_Call struct {
	*mock.Call
}

// UserFixedDependencyVulns is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - doRiskManagement bool
func (_e *AssetDependencyVulnService_Expecter) UserFixedDependencyVulns(tx interface{}, userID interface{}, dependencyVulns interface{}, doRiskManagement interface{}) *AssetDependencyVulnService_UserFixedDependencyVulns_Call {
	return &AssetDependencyVulnService_UserFixedDependencyVulns_Call{Call: _e.mock.On("UserFixedDependencyVulns", tx, userID, dependencyVulns, doRiskManagement)}
}

func (_c *AssetDependencyVulnService_UserFixedDependencyVulns_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVulnerability, doRiskManagement bool)) *AssetDependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVulnerability), args[3].(bool))
	})
	return _c
}

func (_c *AssetDependencyVulnService_UserFixedDependencyVulns_Call) Return(_a0 error) *AssetDependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetDependencyVulnService_UserFixedDependencyVulns_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVulnerability, bool) error) *AssetDependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Return(run)
	return _c
}

// NewAssetDependencyVulnService creates a new instance of AssetDependencyVulnService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetDependencyVulnService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetDependencyVulnService {
	mock := &AssetDependencyVulnService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
