// Code generated by mockery v2.53.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// AffectedComponentRepository is an autogenerated mock type for the AffectedComponentRepository type
type AffectedComponentRepository struct {
	mock.Mock
}

type AffectedComponentRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *AffectedComponentRepository) EXPECT() *AffectedComponentRepository_Expecter {
	return &AffectedComponentRepository_Expecter{mock: &_m.Mock}
}

// DeleteAll provides a mock function with given fields: tx, ecosystem
func (_m *AffectedComponentRepository) DeleteAll(tx *gorm.DB, ecosystem string) error {
	ret := _m.Called(tx, ecosystem)

	if len(ret) == 0 {
		panic("no return value specified for DeleteAll")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, ecosystem)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AffectedComponentRepository_DeleteAll_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteAll'
type AffectedComponentRepository_DeleteAll_Call struct {
	*mock.Call
}

// DeleteAll is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ecosystem string
func (_e *AffectedComponentRepository_Expecter) DeleteAll(tx interface{}, ecosystem interface{}) *AffectedComponentRepository_DeleteAll_Call {
	return &AffectedComponentRepository_DeleteAll_Call{Call: _e.mock.On("DeleteAll", tx, ecosystem)}
}

func (_c *AffectedComponentRepository_DeleteAll_Call) Run(run func(tx *gorm.DB, ecosystem string)) *AffectedComponentRepository_DeleteAll_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *AffectedComponentRepository_DeleteAll_Call) Return(_a0 error) *AffectedComponentRepository_DeleteAll_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AffectedComponentRepository_DeleteAll_Call) RunAndReturn(run func(*gorm.DB, string) error) *AffectedComponentRepository_DeleteAll_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllAffectedComponentsID provides a mock function with no fields
func (_m *AffectedComponentRepository) GetAllAffectedComponentsID() ([]string, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetAllAffectedComponentsID")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]string, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AffectedComponentRepository_GetAllAffectedComponentsID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllAffectedComponentsID'
type AffectedComponentRepository_GetAllAffectedComponentsID_Call struct {
	*mock.Call
}

// GetAllAffectedComponentsID is a helper method to define mock.On call
func (_e *AffectedComponentRepository_Expecter) GetAllAffectedComponentsID() *AffectedComponentRepository_GetAllAffectedComponentsID_Call {
	return &AffectedComponentRepository_GetAllAffectedComponentsID_Call{Call: _e.mock.On("GetAllAffectedComponentsID")}
}

func (_c *AffectedComponentRepository_GetAllAffectedComponentsID_Call) Run(run func()) *AffectedComponentRepository_GetAllAffectedComponentsID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *AffectedComponentRepository_GetAllAffectedComponentsID_Call) Return(_a0 []string, _a1 error) *AffectedComponentRepository_GetAllAffectedComponentsID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AffectedComponentRepository_GetAllAffectedComponentsID_Call) RunAndReturn(run func() ([]string, error)) *AffectedComponentRepository_GetAllAffectedComponentsID_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, affectedComponent
func (_m *AffectedComponentRepository) Save(tx *gorm.DB, affectedComponent *models.AffectedComponent) error {
	ret := _m.Called(tx, affectedComponent)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.AffectedComponent) error); ok {
		r0 = rf(tx, affectedComponent)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AffectedComponentRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type AffectedComponentRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - affectedComponent *models.AffectedComponent
func (_e *AffectedComponentRepository_Expecter) Save(tx interface{}, affectedComponent interface{}) *AffectedComponentRepository_Save_Call {
	return &AffectedComponentRepository_Save_Call{Call: _e.mock.On("Save", tx, affectedComponent)}
}

func (_c *AffectedComponentRepository_Save_Call) Run(run func(tx *gorm.DB, affectedComponent *models.AffectedComponent)) *AffectedComponentRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.AffectedComponent))
	})
	return _c
}

func (_c *AffectedComponentRepository_Save_Call) Return(_a0 error) *AffectedComponentRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AffectedComponentRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.AffectedComponent) error) *AffectedComponentRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, affectedPkgs
func (_m *AffectedComponentRepository) SaveBatch(tx *gorm.DB, affectedPkgs []models.AffectedComponent) error {
	ret := _m.Called(tx, affectedPkgs)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.AffectedComponent) error); ok {
		r0 = rf(tx, affectedPkgs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AffectedComponentRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type AffectedComponentRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - affectedPkgs []models.AffectedComponent
func (_e *AffectedComponentRepository_Expecter) SaveBatch(tx interface{}, affectedPkgs interface{}) *AffectedComponentRepository_SaveBatch_Call {
	return &AffectedComponentRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, affectedPkgs)}
}

func (_c *AffectedComponentRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, affectedPkgs []models.AffectedComponent)) *AffectedComponentRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.AffectedComponent))
	})
	return _c
}

func (_c *AffectedComponentRepository_SaveBatch_Call) Return(_a0 error) *AffectedComponentRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AffectedComponentRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.AffectedComponent) error) *AffectedComponentRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewAffectedComponentRepository creates a new instance of AffectedComponentRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAffectedComponentRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *AffectedComponentRepository {
	mock := &AffectedComponentRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
