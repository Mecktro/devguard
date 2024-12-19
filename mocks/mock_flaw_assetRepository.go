// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	core "github.com/l3montree-dev/devguard/internal/core"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// FlawAssetRepository is an autogenerated mock type for the assetRepository type
type FlawAssetRepository struct {
	mock.Mock
}

type FlawAssetRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *FlawAssetRepository) EXPECT() *FlawAssetRepository_Expecter {
	return &FlawAssetRepository_Expecter{mock: &_m.Mock}
}

// GetAllAssetsFromDB provides a mock function with given fields:
func (_m *FlawAssetRepository) GetAllAssetsFromDB() ([]models.Asset, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetAllAssetsFromDB")
	}

	var r0 []models.Asset
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]models.Asset, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []models.Asset); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Asset)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FlawAssetRepository_GetAllAssetsFromDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllAssetsFromDB'
type FlawAssetRepository_GetAllAssetsFromDB_Call struct {
	*mock.Call
}

// GetAllAssetsFromDB is a helper method to define mock.On call
func (_e *FlawAssetRepository_Expecter) GetAllAssetsFromDB() *FlawAssetRepository_GetAllAssetsFromDB_Call {
	return &FlawAssetRepository_GetAllAssetsFromDB_Call{Call: _e.mock.On("GetAllAssetsFromDB")}
}

func (_c *FlawAssetRepository_GetAllAssetsFromDB_Call) Run(run func()) *FlawAssetRepository_GetAllAssetsFromDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *FlawAssetRepository_GetAllAssetsFromDB_Call) Return(_a0 []models.Asset, _a1 error) *FlawAssetRepository_GetAllAssetsFromDB_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *FlawAssetRepository_GetAllAssetsFromDB_Call) RunAndReturn(run func() ([]models.Asset, error)) *FlawAssetRepository_GetAllAssetsFromDB_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: tx, asset
func (_m *FlawAssetRepository) Update(tx core.DB, asset *models.Asset) error {
	ret := _m.Called(tx, asset)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(core.DB, *models.Asset) error); ok {
		r0 = rf(tx, asset)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawAssetRepository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type FlawAssetRepository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - tx core.DB
//   - asset *models.Asset
func (_e *FlawAssetRepository_Expecter) Update(tx interface{}, asset interface{}) *FlawAssetRepository_Update_Call {
	return &FlawAssetRepository_Update_Call{Call: _e.mock.On("Update", tx, asset)}
}

func (_c *FlawAssetRepository_Update_Call) Run(run func(tx core.DB, asset *models.Asset)) *FlawAssetRepository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.DB), args[1].(*models.Asset))
	})
	return _c
}

func (_c *FlawAssetRepository_Update_Call) Return(_a0 error) *FlawAssetRepository_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawAssetRepository_Update_Call) RunAndReturn(run func(core.DB, *models.Asset) error) *FlawAssetRepository_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewFlawAssetRepository creates a new instance of FlawAssetRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFlawAssetRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *FlawAssetRepository {
	mock := &FlawAssetRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
