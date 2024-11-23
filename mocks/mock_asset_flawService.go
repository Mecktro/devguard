// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// AssetFlawService is an autogenerated mock type for the flawService type
type AssetFlawService struct {
	mock.Mock
}

type AssetFlawService_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetFlawService) EXPECT() *AssetFlawService_Expecter {
	return &AssetFlawService_Expecter{mock: &_m.Mock}
}

// RecalculateRawRiskAssessment provides a mock function with given fields: tx, userID, flaws, justification, _a4
func (_m *AssetFlawService) RecalculateRawRiskAssessment(tx *gorm.DB, userID string, flaws []models.Flaw, justification string, _a4 models.Asset) error {
	ret := _m.Called(tx, userID, flaws, justification, _a4)

	if len(ret) == 0 {
		panic("no return value specified for RecalculateRawRiskAssessment")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.Flaw, string, models.Asset) error); ok {
		r0 = rf(tx, userID, flaws, justification, _a4)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetFlawService_RecalculateRawRiskAssessment_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecalculateRawRiskAssessment'
type AssetFlawService_RecalculateRawRiskAssessment_Call struct {
	*mock.Call
}

// RecalculateRawRiskAssessment is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - flaws []models.Flaw
//   - justification string
//   - _a4 models.Asset
func (_e *AssetFlawService_Expecter) RecalculateRawRiskAssessment(tx interface{}, userID interface{}, flaws interface{}, justification interface{}, _a4 interface{}) *AssetFlawService_RecalculateRawRiskAssessment_Call {
	return &AssetFlawService_RecalculateRawRiskAssessment_Call{Call: _e.mock.On("RecalculateRawRiskAssessment", tx, userID, flaws, justification, _a4)}
}

func (_c *AssetFlawService_RecalculateRawRiskAssessment_Call) Run(run func(tx *gorm.DB, userID string, flaws []models.Flaw, justification string, _a4 models.Asset)) *AssetFlawService_RecalculateRawRiskAssessment_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.Flaw), args[3].(string), args[4].(models.Asset))
	})
	return _c
}

func (_c *AssetFlawService_RecalculateRawRiskAssessment_Call) Return(_a0 error) *AssetFlawService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetFlawService_RecalculateRawRiskAssessment_Call) RunAndReturn(run func(*gorm.DB, string, []models.Flaw, string, models.Asset) error) *AssetFlawService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateFlawState provides a mock function with given fields: tx, userID, flaw, statusType, justification
func (_m *AssetFlawService) UpdateFlawState(tx *gorm.DB, userID string, flaw *models.Flaw, statusType string, justification string) (models.FlawEvent, error) {
	ret := _m.Called(tx, userID, flaw, statusType, justification)

	if len(ret) == 0 {
		panic("no return value specified for UpdateFlawState")
	}

	var r0 models.FlawEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.Flaw, string, string) (models.FlawEvent, error)); ok {
		return rf(tx, userID, flaw, statusType, justification)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.Flaw, string, string) models.FlawEvent); ok {
		r0 = rf(tx, userID, flaw, statusType, justification)
	} else {
		r0 = ret.Get(0).(models.FlawEvent)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string, *models.Flaw, string, string) error); ok {
		r1 = rf(tx, userID, flaw, statusType, justification)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetFlawService_UpdateFlawState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateFlawState'
type AssetFlawService_UpdateFlawState_Call struct {
	*mock.Call
}

// UpdateFlawState is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - flaw *models.Flaw
//   - statusType string
//   - justification string
func (_e *AssetFlawService_Expecter) UpdateFlawState(tx interface{}, userID interface{}, flaw interface{}, statusType interface{}, justification interface{}) *AssetFlawService_UpdateFlawState_Call {
	return &AssetFlawService_UpdateFlawState_Call{Call: _e.mock.On("UpdateFlawState", tx, userID, flaw, statusType, justification)}
}

func (_c *AssetFlawService_UpdateFlawState_Call) Run(run func(tx *gorm.DB, userID string, flaw *models.Flaw, statusType string, justification string)) *AssetFlawService_UpdateFlawState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].(*models.Flaw), args[3].(string), args[4].(string))
	})
	return _c
}

func (_c *AssetFlawService_UpdateFlawState_Call) Return(_a0 models.FlawEvent, _a1 error) *AssetFlawService_UpdateFlawState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetFlawService_UpdateFlawState_Call) RunAndReturn(run func(*gorm.DB, string, *models.Flaw, string, string) (models.FlawEvent, error)) *AssetFlawService_UpdateFlawState_Call {
	_c.Call.Return(run)
	return _c
}

// UserDetectedFlaws provides a mock function with given fields: tx, userID, flaws, _a3, doRiskManagement
func (_m *AssetFlawService) UserDetectedFlaws(tx *gorm.DB, userID string, flaws []models.Flaw, _a3 models.Asset, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, flaws, _a3, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserDetectedFlaws")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.Flaw, models.Asset, bool) error); ok {
		r0 = rf(tx, userID, flaws, _a3, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetFlawService_UserDetectedFlaws_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserDetectedFlaws'
type AssetFlawService_UserDetectedFlaws_Call struct {
	*mock.Call
}

// UserDetectedFlaws is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - flaws []models.Flaw
//   - _a3 models.Asset
//   - doRiskManagement bool
func (_e *AssetFlawService_Expecter) UserDetectedFlaws(tx interface{}, userID interface{}, flaws interface{}, _a3 interface{}, doRiskManagement interface{}) *AssetFlawService_UserDetectedFlaws_Call {
	return &AssetFlawService_UserDetectedFlaws_Call{Call: _e.mock.On("UserDetectedFlaws", tx, userID, flaws, _a3, doRiskManagement)}
}

func (_c *AssetFlawService_UserDetectedFlaws_Call) Run(run func(tx *gorm.DB, userID string, flaws []models.Flaw, _a3 models.Asset, doRiskManagement bool)) *AssetFlawService_UserDetectedFlaws_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.Flaw), args[3].(models.Asset), args[4].(bool))
	})
	return _c
}

func (_c *AssetFlawService_UserDetectedFlaws_Call) Return(_a0 error) *AssetFlawService_UserDetectedFlaws_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetFlawService_UserDetectedFlaws_Call) RunAndReturn(run func(*gorm.DB, string, []models.Flaw, models.Asset, bool) error) *AssetFlawService_UserDetectedFlaws_Call {
	_c.Call.Return(run)
	return _c
}

// UserFixedFlaws provides a mock function with given fields: tx, userID, flaws, doRiskManagement
func (_m *AssetFlawService) UserFixedFlaws(tx *gorm.DB, userID string, flaws []models.Flaw, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, flaws, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserFixedFlaws")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.Flaw, bool) error); ok {
		r0 = rf(tx, userID, flaws, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AssetFlawService_UserFixedFlaws_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserFixedFlaws'
type AssetFlawService_UserFixedFlaws_Call struct {
	*mock.Call
}

// UserFixedFlaws is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - flaws []models.Flaw
//   - doRiskManagement bool
func (_e *AssetFlawService_Expecter) UserFixedFlaws(tx interface{}, userID interface{}, flaws interface{}, doRiskManagement interface{}) *AssetFlawService_UserFixedFlaws_Call {
	return &AssetFlawService_UserFixedFlaws_Call{Call: _e.mock.On("UserFixedFlaws", tx, userID, flaws, doRiskManagement)}
}

func (_c *AssetFlawService_UserFixedFlaws_Call) Run(run func(tx *gorm.DB, userID string, flaws []models.Flaw, doRiskManagement bool)) *AssetFlawService_UserFixedFlaws_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.Flaw), args[3].(bool))
	})
	return _c
}

func (_c *AssetFlawService_UserFixedFlaws_Call) Return(_a0 error) *AssetFlawService_UserFixedFlaws_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetFlawService_UserFixedFlaws_Call) RunAndReturn(run func(*gorm.DB, string, []models.Flaw, bool) error) *AssetFlawService_UserFixedFlaws_Call {
	_c.Call.Return(run)
	return _c
}

// NewAssetFlawService creates a new instance of AssetFlawService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetFlawService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetFlawService {
	mock := &AssetFlawService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
