// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// FlawFlawRepository is an autogenerated mock type for the flawRepository type
type FlawFlawRepository struct {
	mock.Mock
}

type FlawFlawRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *FlawFlawRepository) EXPECT() *FlawFlawRepository_Expecter {
	return &FlawFlawRepository_Expecter{mock: &_m.Mock}
}

// Begin provides a mock function with no fields
func (_m *FlawFlawRepository) Begin() *gorm.DB {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Begin")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func() *gorm.DB); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// FlawFlawRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type FlawFlawRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *FlawFlawRepository_Expecter) Begin() *FlawFlawRepository_Begin_Call {
	return &FlawFlawRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *FlawFlawRepository_Begin_Call) Run(run func()) *FlawFlawRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *FlawFlawRepository_Begin_Call) Return(_a0 *gorm.DB) *FlawFlawRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawFlawRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *FlawFlawRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllFlawsByAssetID provides a mock function with given fields: tx, assetID
func (_m *FlawFlawRepository) GetAllFlawsByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVulnerability, error) {
	ret := _m.Called(tx, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllFlawsByAssetID")
	}

	var r0 []models.DependencyVulnerability
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) ([]models.DependencyVulnerability, error)); ok {
		return rf(tx, assetID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) []models.DependencyVulnerability); ok {
		r0 = rf(tx, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVulnerability)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID) error); ok {
		r1 = rf(tx, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawFlawRepository_GetAllFlawsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllFlawsByAssetID'
type FlawFlawRepository_GetAllFlawsByAssetID_Call struct {
	*mock.Call
}

// GetAllFlawsByAssetID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
func (_e *FlawFlawRepository_Expecter) GetAllFlawsByAssetID(tx interface{}, assetID interface{}) *FlawFlawRepository_GetAllFlawsByAssetID_Call {
	return &FlawFlawRepository_GetAllFlawsByAssetID_Call{Call: _e.mock.On("GetAllFlawsByAssetID", tx, assetID)}
}

func (_c *FlawFlawRepository_GetAllFlawsByAssetID_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID)) *FlawFlawRepository_GetAllFlawsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *FlawFlawRepository_GetAllFlawsByAssetID_Call) Return(_a0 []models.DependencyVulnerability, _a1 error) *FlawFlawRepository_GetAllFlawsByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawFlawRepository_GetAllFlawsByAssetID_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.DependencyVulnerability, error)) *FlawFlawRepository_GetAllFlawsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: db, flaws
func (_m *FlawFlawRepository) Save(db *gorm.DB, flaws *models.DependencyVulnerability) error {
	ret := _m.Called(db, flaws)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.DependencyVulnerability) error); ok {
		r0 = rf(db, flaws)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawFlawRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type FlawFlawRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - flaws *models.Flaw
func (_e *FlawFlawRepository_Expecter) Save(db interface{}, flaws interface{}) *FlawFlawRepository_Save_Call {
	return &FlawFlawRepository_Save_Call{Call: _e.mock.On("Save", db, flaws)}
}

func (_c *FlawFlawRepository_Save_Call) Run(run func(db *gorm.DB, flaws *models.DependencyVulnerability)) *FlawFlawRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.DependencyVulnerability))
	})
	return _c
}

func (_c *FlawFlawRepository_Save_Call) Return(_a0 error) *FlawFlawRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawFlawRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.DependencyVulnerability) error) *FlawFlawRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: db, flaws
func (_m *FlawFlawRepository) SaveBatch(db *gorm.DB, flaws []models.DependencyVulnerability) error {
	ret := _m.Called(db, flaws)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.DependencyVulnerability) error); ok {
		r0 = rf(db, flaws)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawFlawRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type FlawFlawRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - db *gorm.DB
//   - flaws []models.Flaw
func (_e *FlawFlawRepository_Expecter) SaveBatch(db interface{}, flaws interface{}) *FlawFlawRepository_SaveBatch_Call {
	return &FlawFlawRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", db, flaws)}
}

func (_c *FlawFlawRepository_SaveBatch_Call) Run(run func(db *gorm.DB, flaws []models.DependencyVulnerability)) *FlawFlawRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.DependencyVulnerability))
	})
	return _c
}

func (_c *FlawFlawRepository_SaveBatch_Call) Return(_a0 error) *FlawFlawRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawFlawRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.DependencyVulnerability) error) *FlawFlawRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: txFunc
func (_m *FlawFlawRepository) Transaction(txFunc func(*gorm.DB) error) error {
	ret := _m.Called(txFunc)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(*gorm.DB) error) error); ok {
		r0 = rf(txFunc)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawFlawRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type FlawFlawRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - txFunc func(*gorm.DB) error
func (_e *FlawFlawRepository_Expecter) Transaction(txFunc interface{}) *FlawFlawRepository_Transaction_Call {
	return &FlawFlawRepository_Transaction_Call{Call: _e.mock.On("Transaction", txFunc)}
}

func (_c *FlawFlawRepository_Transaction_Call) Run(run func(txFunc func(*gorm.DB) error)) *FlawFlawRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *FlawFlawRepository_Transaction_Call) Return(_a0 error) *FlawFlawRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawFlawRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *FlawFlawRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewFlawFlawRepository creates a new instance of FlawFlawRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFlawFlawRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *FlawFlawRepository {
	mock := &FlawFlawRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
