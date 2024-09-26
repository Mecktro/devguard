// Code generated by mockery v2.42.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// ConfigConfigRepository is an autogenerated mock type for the configRepository type
type ConfigConfigRepository struct {
	mock.Mock
}

type ConfigConfigRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ConfigConfigRepository) EXPECT() *ConfigConfigRepository_Expecter {
	return &ConfigConfigRepository_Expecter{mock: &_m.Mock}
}

// GetDB provides a mock function with given fields: tx
func (_m *ConfigConfigRepository) GetDB(tx *gorm.DB) *gorm.DB {
	ret := _m.Called(tx)

	if len(ret) == 0 {
		panic("no return value specified for GetDB")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func(*gorm.DB) *gorm.DB); ok {
		r0 = rf(tx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// ConfigConfigRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type ConfigConfigRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *ConfigConfigRepository_Expecter) GetDB(tx interface{}) *ConfigConfigRepository_GetDB_Call {
	return &ConfigConfigRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *ConfigConfigRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *ConfigConfigRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *ConfigConfigRepository_GetDB_Call) Return(_a0 *gorm.DB) *ConfigConfigRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ConfigConfigRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *ConfigConfigRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, _a1
func (_m *ConfigConfigRepository) Save(tx *gorm.DB, _a1 *models.Config) error {
	ret := _m.Called(tx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Config) error); ok {
		r0 = rf(tx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfigConfigRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type ConfigConfigRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - _a1 *models.Config
func (_e *ConfigConfigRepository_Expecter) Save(tx interface{}, _a1 interface{}) *ConfigConfigRepository_Save_Call {
	return &ConfigConfigRepository_Save_Call{Call: _e.mock.On("Save", tx, _a1)}
}

func (_c *ConfigConfigRepository_Save_Call) Run(run func(tx *gorm.DB, _a1 *models.Config)) *ConfigConfigRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Config))
	})
	return _c
}

func (_c *ConfigConfigRepository_Save_Call) Return(_a0 error) *ConfigConfigRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ConfigConfigRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Config) error) *ConfigConfigRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewConfigConfigRepository creates a new instance of ConfigConfigRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewConfigConfigRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ConfigConfigRepository {
	mock := &ConfigConfigRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
