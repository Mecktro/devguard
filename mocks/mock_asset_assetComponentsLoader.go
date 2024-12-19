// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	core "github.com/l3montree-dev/devguard/internal/core"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// AssetAssetComponentsLoader is an autogenerated mock type for the assetComponentsLoader type
type AssetAssetComponentsLoader struct {
	mock.Mock
}

type AssetAssetComponentsLoader_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetAssetComponentsLoader) EXPECT() *AssetAssetComponentsLoader_Expecter {
	return &AssetAssetComponentsLoader_Expecter{mock: &_m.Mock}
}

// GetVersions provides a mock function with given fields: tx, _a1
func (_m *AssetAssetComponentsLoader) GetVersions(tx core.DB, _a1 models.Asset) ([]string, error) {
	ret := _m.Called(tx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for GetVersions")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(core.DB, models.Asset) ([]string, error)); ok {
		return rf(tx, _a1)
	}
	if rf, ok := ret.Get(0).(func(core.DB, models.Asset) []string); ok {
		r0 = rf(tx, _a1)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(core.DB, models.Asset) error); ok {
		r1 = rf(tx, _a1)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetAssetComponentsLoader_GetVersions_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetVersions'
type AssetAssetComponentsLoader_GetVersions_Call struct {
	*mock.Call
}

// GetVersions is a helper method to define mock.On call
//   - tx core.DB
//   - _a1 models.Asset
func (_e *AssetAssetComponentsLoader_Expecter) GetVersions(tx interface{}, _a1 interface{}) *AssetAssetComponentsLoader_GetVersions_Call {
	return &AssetAssetComponentsLoader_GetVersions_Call{Call: _e.mock.On("GetVersions", tx, _a1)}
}

func (_c *AssetAssetComponentsLoader_GetVersions_Call) Run(run func(tx core.DB, _a1 models.Asset)) *AssetAssetComponentsLoader_GetVersions_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.DB), args[1].(models.Asset))
	})
	return _c
}

func (_c *AssetAssetComponentsLoader_GetVersions_Call) Return(_a0 []string, _a1 error) *AssetAssetComponentsLoader_GetVersions_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetAssetComponentsLoader_GetVersions_Call) RunAndReturn(run func(core.DB, models.Asset) ([]string, error)) *AssetAssetComponentsLoader_GetVersions_Call {
	_c.Call.Return(run)
	return _c
}

// LoadComponents provides a mock function with given fields: tx, _a1, scanType, version
func (_m *AssetAssetComponentsLoader) LoadComponents(tx core.DB, _a1 models.Asset, scanType string, version string) ([]models.ComponentDependency, error) {
	ret := _m.Called(tx, _a1, scanType, version)

	if len(ret) == 0 {
		panic("no return value specified for LoadComponents")
	}

	var r0 []models.ComponentDependency
	var r1 error
	if rf, ok := ret.Get(0).(func(core.DB, models.Asset, string, string) ([]models.ComponentDependency, error)); ok {
		return rf(tx, _a1, scanType, version)
	}
	if rf, ok := ret.Get(0).(func(core.DB, models.Asset, string, string) []models.ComponentDependency); ok {
		r0 = rf(tx, _a1, scanType, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ComponentDependency)
		}
	}

	if rf, ok := ret.Get(1).(func(core.DB, models.Asset, string, string) error); ok {
		r1 = rf(tx, _a1, scanType, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetAssetComponentsLoader_LoadComponents_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LoadComponents'
type AssetAssetComponentsLoader_LoadComponents_Call struct {
	*mock.Call
}

// LoadComponents is a helper method to define mock.On call
//   - tx core.DB
//   - _a1 models.Asset
//   - scanType string
//   - version string
func (_e *AssetAssetComponentsLoader_Expecter) LoadComponents(tx interface{}, _a1 interface{}, scanType interface{}, version interface{}) *AssetAssetComponentsLoader_LoadComponents_Call {
	return &AssetAssetComponentsLoader_LoadComponents_Call{Call: _e.mock.On("LoadComponents", tx, _a1, scanType, version)}
}

func (_c *AssetAssetComponentsLoader_LoadComponents_Call) Run(run func(tx core.DB, _a1 models.Asset, scanType string, version string)) *AssetAssetComponentsLoader_LoadComponents_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.DB), args[1].(models.Asset), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *AssetAssetComponentsLoader_LoadComponents_Call) Return(_a0 []models.ComponentDependency, _a1 error) *AssetAssetComponentsLoader_LoadComponents_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetAssetComponentsLoader_LoadComponents_Call) RunAndReturn(run func(core.DB, models.Asset, string, string) ([]models.ComponentDependency, error)) *AssetAssetComponentsLoader_LoadComponents_Call {
	_c.Call.Return(run)
	return _c
}

// NewAssetAssetComponentsLoader creates a new instance of AssetAssetComponentsLoader. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetAssetComponentsLoader(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetAssetComponentsLoader {
	mock := &AssetAssetComponentsLoader{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
