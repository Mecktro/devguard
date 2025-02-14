// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// DependencyVulnDependencyVulnRepository is an autogenerated mock type for the dependencyVulnRepository type
type DependencyVulnDependencyVulnRepository struct {
	mock.Mock
}

type DependencyVulnDependencyVulnRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *DependencyVulnDependencyVulnRepository) EXPECT() *DependencyVulnDependencyVulnRepository_Expecter {
	return &DependencyVulnDependencyVulnRepository_Expecter{mock: &_m.Mock}
}

// Begin provides a mock function with no fields
func (_m *DependencyVulnDependencyVulnRepository) Begin() *gorm.DB {
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

// DependencyVulnDependencyVulnRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type DependencyVulnDependencyVulnRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *DependencyVulnDependencyVulnRepository_Expecter) Begin() *DependencyVulnDependencyVulnRepository_Begin_Call {
	return &DependencyVulnDependencyVulnRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *DependencyVulnDependencyVulnRepository_Begin_Call) Run(run func()) *DependencyVulnDependencyVulnRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_Begin_Call) Return(_a0 *gorm.DB) *DependencyVulnDependencyVulnRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *DependencyVulnDependencyVulnRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllVulnsByAssetID provides a mock function with given fields: tx, assetID
func (_m *DependencyVulnDependencyVulnRepository) GetAllVulnsByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVulnerability, error) {
	ret := _m.Called(tx, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllVulnsByAssetID")
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

// DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllVulnsByAssetID'
type DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call struct {
	*mock.Call
}

// GetAllVulnsByAssetID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
func (_e *DependencyVulnDependencyVulnRepository_Expecter) GetAllVulnsByAssetID(tx interface{}, assetID interface{}) *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call {
	return &DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call{Call: _e.mock.On("GetAllVulnsByAssetID", tx, assetID)}
}

func (_c *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID)) *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call) Return(_a0 []models.DependencyVulnerability, _a1 error) *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.DependencyVulnerability, error)) *DependencyVulnDependencyVulnRepository_GetAllVulnsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: db, dependencyVulns
func (_m *DependencyVulnDependencyVulnRepository) Save(db *gorm.DB, dependencyVulns *models.DependencyVulnerability) error {
	ret := _m.Called(db, dependencyVulns)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.DependencyVulnerability) error); ok {
		r0 = rf(db, dependencyVulns)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnDependencyVulnRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type DependencyVulnDependencyVulnRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - dependencyVulns *models.DependencyVuln
func (_e *DependencyVulnDependencyVulnRepository_Expecter) Save(db interface{}, dependencyVulns interface{}) *DependencyVulnDependencyVulnRepository_Save_Call {
	return &DependencyVulnDependencyVulnRepository_Save_Call{Call: _e.mock.On("Save", db, dependencyVulns)}
}

func (_c *DependencyVulnDependencyVulnRepository_Save_Call) Run(run func(db *gorm.DB, dependencyVulns *models.DependencyVulnerability)) *DependencyVulnDependencyVulnRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.DependencyVulnerability))
	})
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_Save_Call) Return(_a0 error) *DependencyVulnDependencyVulnRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.DependencyVulnerability) error) *DependencyVulnDependencyVulnRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: db, dependencyVulns
func (_m *DependencyVulnDependencyVulnRepository) SaveBatch(db *gorm.DB, dependencyVulns []models.DependencyVulnerability) error {
	ret := _m.Called(db, dependencyVulns)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.DependencyVulnerability) error); ok {
		r0 = rf(db, dependencyVulns)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnDependencyVulnRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type DependencyVulnDependencyVulnRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - db *gorm.DB
//   - dependencyVulns []models.DependencyVuln
func (_e *DependencyVulnDependencyVulnRepository_Expecter) SaveBatch(db interface{}, dependencyVulns interface{}) *DependencyVulnDependencyVulnRepository_SaveBatch_Call {
	return &DependencyVulnDependencyVulnRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", db, dependencyVulns)}
}

func (_c *DependencyVulnDependencyVulnRepository_SaveBatch_Call) Run(run func(db *gorm.DB, dependencyVulns []models.DependencyVulnerability)) *DependencyVulnDependencyVulnRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.DependencyVulnerability))
	})
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_SaveBatch_Call) Return(_a0 error) *DependencyVulnDependencyVulnRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.DependencyVulnerability) error) *DependencyVulnDependencyVulnRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: txFunc
func (_m *DependencyVulnDependencyVulnRepository) Transaction(txFunc func(*gorm.DB) error) error {
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

// DependencyVulnDependencyVulnRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type DependencyVulnDependencyVulnRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - txFunc func(*gorm.DB) error
func (_e *DependencyVulnDependencyVulnRepository_Expecter) Transaction(txFunc interface{}) *DependencyVulnDependencyVulnRepository_Transaction_Call {
	return &DependencyVulnDependencyVulnRepository_Transaction_Call{Call: _e.mock.On("Transaction", txFunc)}
}

func (_c *DependencyVulnDependencyVulnRepository_Transaction_Call) Run(run func(txFunc func(*gorm.DB) error)) *DependencyVulnDependencyVulnRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_Transaction_Call) Return(_a0 error) *DependencyVulnDependencyVulnRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnDependencyVulnRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *DependencyVulnDependencyVulnRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewDependencyVulnDependencyVulnRepository creates a new instance of DependencyVulnDependencyVulnRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDependencyVulnDependencyVulnRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *DependencyVulnDependencyVulnRepository {
	mock := &DependencyVulnDependencyVulnRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
