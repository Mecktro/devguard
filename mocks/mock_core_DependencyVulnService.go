// Code generated by mockery v2.53.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// CoreDependencyVulnService is an autogenerated mock type for the DependencyVulnService type
type CoreDependencyVulnService struct {
	mock.Mock
}

type CoreDependencyVulnService_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreDependencyVulnService) EXPECT() *CoreDependencyVulnService_Expecter {
	return &CoreDependencyVulnService_Expecter{mock: &_m.Mock}
}

// CreateIssuesForVulns provides a mock function with given fields: asset, vulnList
func (_m *CoreDependencyVulnService) CreateIssuesForVulns(asset models.Asset, vulnList []models.DependencyVuln) error {
	ret := _m.Called(asset, vulnList)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssuesForVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Asset, []models.DependencyVuln) error); ok {
		r0 = rf(asset, vulnList)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreDependencyVulnService_CreateIssuesForVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssuesForVulns'
type CoreDependencyVulnService_CreateIssuesForVulns_Call struct {
	*mock.Call
}

// CreateIssuesForVulns is a helper method to define mock.On call
//   - asset models.Asset
//   - vulnList []models.DependencyVuln
func (_e *CoreDependencyVulnService_Expecter) CreateIssuesForVulns(asset interface{}, vulnList interface{}) *CoreDependencyVulnService_CreateIssuesForVulns_Call {
	return &CoreDependencyVulnService_CreateIssuesForVulns_Call{Call: _e.mock.On("CreateIssuesForVulns", asset, vulnList)}
}

func (_c *CoreDependencyVulnService_CreateIssuesForVulns_Call) Run(run func(asset models.Asset, vulnList []models.DependencyVuln)) *CoreDependencyVulnService_CreateIssuesForVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].([]models.DependencyVuln))
	})
	return _c
}

func (_c *CoreDependencyVulnService_CreateIssuesForVulns_Call) Return(_a0 error) *CoreDependencyVulnService_CreateIssuesForVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreDependencyVulnService_CreateIssuesForVulns_Call) RunAndReturn(run func(models.Asset, []models.DependencyVuln) error) *CoreDependencyVulnService_CreateIssuesForVulns_Call {
	_c.Call.Return(run)
	return _c
}

// RecalculateRawRiskAssessment provides a mock function with given fields: tx, responsible, dependencyVulns, justification, asset
func (_m *CoreDependencyVulnService) RecalculateRawRiskAssessment(tx *gorm.DB, responsible string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) error {
	ret := _m.Called(tx, responsible, dependencyVulns, justification, asset)

	if len(ret) == 0 {
		panic("no return value specified for RecalculateRawRiskAssessment")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVuln, string, models.Asset) error); ok {
		r0 = rf(tx, responsible, dependencyVulns, justification, asset)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreDependencyVulnService_RecalculateRawRiskAssessment_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecalculateRawRiskAssessment'
type CoreDependencyVulnService_RecalculateRawRiskAssessment_Call struct {
	*mock.Call
}

// RecalculateRawRiskAssessment is a helper method to define mock.On call
//   - tx *gorm.DB
//   - responsible string
//   - dependencyVulns []models.DependencyVuln
//   - justification string
//   - asset models.Asset
func (_e *CoreDependencyVulnService_Expecter) RecalculateRawRiskAssessment(tx interface{}, responsible interface{}, dependencyVulns interface{}, justification interface{}, asset interface{}) *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call {
	return &CoreDependencyVulnService_RecalculateRawRiskAssessment_Call{Call: _e.mock.On("RecalculateRawRiskAssessment", tx, responsible, dependencyVulns, justification, asset)}
}

func (_c *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call) Run(run func(tx *gorm.DB, responsible string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset)) *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVuln), args[3].(string), args[4].(models.Asset))
	})
	return _c
}

func (_c *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call) Return(_a0 error) *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVuln, string, models.Asset) error) *CoreDependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateDependencyVulnState provides a mock function with given fields: tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName
func (_m *CoreDependencyVulnService) UpdateDependencyVulnState(tx *gorm.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, assetVersionName string) (models.VulnEvent, error) {
	ret := _m.Called(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)

	if len(ret) == 0 {
		panic("no return value specified for UpdateDependencyVulnState")
	}

	var r0 models.VulnEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) (models.VulnEvent, error)); ok {
		return rf(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) models.VulnEvent); ok {
		r0 = rf(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)
	} else {
		r0 = ret.Get(0).(models.VulnEvent)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) error); ok {
		r1 = rf(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreDependencyVulnService_UpdateDependencyVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateDependencyVulnState'
type CoreDependencyVulnService_UpdateDependencyVulnState_Call struct {
	*mock.Call
}

// UpdateDependencyVulnState is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
//   - userID string
//   - dependencyVuln *models.DependencyVuln
//   - statusType string
//   - justification string
//   - assetVersionName string
func (_e *CoreDependencyVulnService_Expecter) UpdateDependencyVulnState(tx interface{}, assetID interface{}, userID interface{}, dependencyVuln interface{}, statusType interface{}, justification interface{}, assetVersionName interface{}) *CoreDependencyVulnService_UpdateDependencyVulnState_Call {
	return &CoreDependencyVulnService_UpdateDependencyVulnState_Call{Call: _e.mock.On("UpdateDependencyVulnState", tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)}
}

func (_c *CoreDependencyVulnService_UpdateDependencyVulnState_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, assetVersionName string)) *CoreDependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(string), args[3].(*models.DependencyVuln), args[4].(string), args[5].(string), args[6].(string))
	})
	return _c
}

func (_c *CoreDependencyVulnService_UpdateDependencyVulnState_Call) Return(_a0 models.VulnEvent, _a1 error) *CoreDependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreDependencyVulnService_UpdateDependencyVulnState_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) (models.VulnEvent, error)) *CoreDependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Return(run)
	return _c
}

// UserDetectedDependencyVulns provides a mock function with given fields: tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement
func (_m *CoreDependencyVulnService) UserDetectedDependencyVulns(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserDetectedDependencyVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error); ok {
		r0 = rf(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreDependencyVulnService_UserDetectedDependencyVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserDetectedDependencyVulns'
type CoreDependencyVulnService_UserDetectedDependencyVulns_Call struct {
	*mock.Call
}

// UserDetectedDependencyVulns is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - assetVersion models.AssetVersion
//   - asset models.Asset
//   - doRiskManagement bool
func (_e *CoreDependencyVulnService_Expecter) UserDetectedDependencyVulns(tx interface{}, userID interface{}, dependencyVulns interface{}, assetVersion interface{}, asset interface{}, doRiskManagement interface{}) *CoreDependencyVulnService_UserDetectedDependencyVulns_Call {
	return &CoreDependencyVulnService_UserDetectedDependencyVulns_Call{Call: _e.mock.On("UserDetectedDependencyVulns", tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)}
}

func (_c *CoreDependencyVulnService_UserDetectedDependencyVulns_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool)) *CoreDependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVuln), args[3].(models.AssetVersion), args[4].(models.Asset), args[5].(bool))
	})
	return _c
}

func (_c *CoreDependencyVulnService_UserDetectedDependencyVulns_Call) Return(_a0 error) *CoreDependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreDependencyVulnService_UserDetectedDependencyVulns_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error) *CoreDependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Return(run)
	return _c
}

// UserFixedDependencyVulns provides a mock function with given fields: tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement
func (_m *CoreDependencyVulnService) UserFixedDependencyVulns(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserFixedDependencyVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error); ok {
		r0 = rf(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreDependencyVulnService_UserFixedDependencyVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserFixedDependencyVulns'
type CoreDependencyVulnService_UserFixedDependencyVulns_Call struct {
	*mock.Call
}

// UserFixedDependencyVulns is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - assetVersion models.AssetVersion
//   - asset models.Asset
//   - doRiskManagement bool
func (_e *CoreDependencyVulnService_Expecter) UserFixedDependencyVulns(tx interface{}, userID interface{}, dependencyVulns interface{}, assetVersion interface{}, asset interface{}, doRiskManagement interface{}) *CoreDependencyVulnService_UserFixedDependencyVulns_Call {
	return &CoreDependencyVulnService_UserFixedDependencyVulns_Call{Call: _e.mock.On("UserFixedDependencyVulns", tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)}
}

func (_c *CoreDependencyVulnService_UserFixedDependencyVulns_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool)) *CoreDependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVuln), args[3].(models.AssetVersion), args[4].(models.Asset), args[5].(bool))
	})
	return _c
}

func (_c *CoreDependencyVulnService_UserFixedDependencyVulns_Call) Return(_a0 error) *CoreDependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreDependencyVulnService_UserFixedDependencyVulns_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error) *CoreDependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreDependencyVulnService creates a new instance of CoreDependencyVulnService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreDependencyVulnService(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreDependencyVulnService {
	mock := &CoreDependencyVulnService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
