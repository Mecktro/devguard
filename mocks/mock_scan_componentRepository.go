// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// ScanComponentRepository is an autogenerated mock type for the componentRepository type
type ScanComponentRepository struct {
	mock.Mock
}

type ScanComponentRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ScanComponentRepository) EXPECT() *ScanComponentRepository_Expecter {
	return &ScanComponentRepository_Expecter{mock: &_m.Mock}
}

// LoadComponents provides a mock function with given fields: tx, assetVersionName, assetID, scannerID, version
func (_m *ScanComponentRepository) LoadComponents(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, scannerID string, version string) ([]models.ComponentDependency, error) {
	ret := _m.Called(tx, assetVersionName, assetID, scannerID, version)

	if len(ret) == 0 {
		panic("no return value specified for LoadComponents")
	}

	var r0 []models.ComponentDependency
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, uuid.UUID, string, string) ([]models.ComponentDependency, error)); ok {
		return rf(tx, assetVersionName, assetID, scannerID, version)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, uuid.UUID, string, string) []models.ComponentDependency); ok {
		r0 = rf(tx, assetVersionName, assetID, scannerID, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ComponentDependency)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string, uuid.UUID, string, string) error); ok {
		r1 = rf(tx, assetVersionName, assetID, scannerID, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ScanComponentRepository_LoadComponents_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LoadComponents'
type ScanComponentRepository_LoadComponents_Call struct {
	*mock.Call
}

// LoadComponents is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetVersionName string
//   - assetID uuid.UUID
//   - scannerID string
//   - version string
func (_e *ScanComponentRepository_Expecter) LoadComponents(tx interface{}, assetVersionName interface{}, assetID interface{}, scannerID interface{}, version interface{}) *ScanComponentRepository_LoadComponents_Call {
	return &ScanComponentRepository_LoadComponents_Call{Call: _e.mock.On("LoadComponents", tx, assetVersionName, assetID, scannerID, version)}
}

func (_c *ScanComponentRepository_LoadComponents_Call) Run(run func(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, scannerID string, version string)) *ScanComponentRepository_LoadComponents_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].(uuid.UUID), args[3].(string), args[4].(string))
	})
	return _c
}

func (_c *ScanComponentRepository_LoadComponents_Call) Return(_a0 []models.ComponentDependency, _a1 error) *ScanComponentRepository_LoadComponents_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ScanComponentRepository_LoadComponents_Call) RunAndReturn(run func(*gorm.DB, string, uuid.UUID, string, string) ([]models.ComponentDependency, error)) *ScanComponentRepository_LoadComponents_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, components
func (_m *ScanComponentRepository) SaveBatch(tx *gorm.DB, components []models.Component) error {
	ret := _m.Called(tx, components)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.Component) error); ok {
		r0 = rf(tx, components)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ScanComponentRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type ScanComponentRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - components []models.Component
func (_e *ScanComponentRepository_Expecter) SaveBatch(tx interface{}, components interface{}) *ScanComponentRepository_SaveBatch_Call {
	return &ScanComponentRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, components)}
}

func (_c *ScanComponentRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, components []models.Component)) *ScanComponentRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.Component))
	})
	return _c
}

func (_c *ScanComponentRepository_SaveBatch_Call) Return(_a0 error) *ScanComponentRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ScanComponentRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.Component) error) *ScanComponentRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewScanComponentRepository creates a new instance of ScanComponentRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewScanComponentRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ScanComponentRepository {
	mock := &ScanComponentRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
