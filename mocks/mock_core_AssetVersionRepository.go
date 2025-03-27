// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// CoreAssetVersionRepository is an autogenerated mock type for the AssetVersionRepository type
type CoreAssetVersionRepository struct {
	mock.Mock
}

type CoreAssetVersionRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreAssetVersionRepository) EXPECT() *CoreAssetVersionRepository_Expecter {
	return &CoreAssetVersionRepository_Expecter{mock: &_m.Mock}
}

// All provides a mock function with no fields
func (_m *CoreAssetVersionRepository) All() ([]models.AssetVersion, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for All")
	}

	var r0 []models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]models.AssetVersion, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []models.AssetVersion); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetVersion)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetVersionRepository_All_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'All'
type CoreAssetVersionRepository_All_Call struct {
	*mock.Call
}

// All is a helper method to define mock.On call
func (_e *CoreAssetVersionRepository_Expecter) All() *CoreAssetVersionRepository_All_Call {
	return &CoreAssetVersionRepository_All_Call{Call: _e.mock.On("All")}
}

func (_c *CoreAssetVersionRepository_All_Call) Run(run func()) *CoreAssetVersionRepository_All_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreAssetVersionRepository_All_Call) Return(_a0 []models.AssetVersion, _a1 error) *CoreAssetVersionRepository_All_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionRepository_All_Call) RunAndReturn(run func() ([]models.AssetVersion, error)) *CoreAssetVersionRepository_All_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, assetVersion
func (_m *CoreAssetVersionRepository) Delete(tx *gorm.DB, assetVersion *models.AssetVersion) error {
	ret := _m.Called(tx, assetVersion)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.AssetVersion) error); ok {
		r0 = rf(tx, assetVersion)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreAssetVersionRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type CoreAssetVersionRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetVersion *models.AssetVersion
func (_e *CoreAssetVersionRepository_Expecter) Delete(tx interface{}, assetVersion interface{}) *CoreAssetVersionRepository_Delete_Call {
	return &CoreAssetVersionRepository_Delete_Call{Call: _e.mock.On("Delete", tx, assetVersion)}
}

func (_c *CoreAssetVersionRepository_Delete_Call) Run(run func(tx *gorm.DB, assetVersion *models.AssetVersion)) *CoreAssetVersionRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.AssetVersion))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_Delete_Call) Return(_a0 error) *CoreAssetVersionRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetVersionRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, *models.AssetVersion) error) *CoreAssetVersionRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// FindOrCreate provides a mock function with given fields: assetVersionName, assetID, tag, defaultBranchName
func (_m *CoreAssetVersionRepository) FindOrCreate(assetVersionName string, assetID uuid.UUID, tag string, defaultBranchName string) (models.AssetVersion, error) {
	ret := _m.Called(assetVersionName, assetID, tag, defaultBranchName)

	if len(ret) == 0 {
		panic("no return value specified for FindOrCreate")
	}

	var r0 models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string, string) (models.AssetVersion, error)); ok {
		return rf(assetVersionName, assetID, tag, defaultBranchName)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string, string) models.AssetVersion); ok {
		r0 = rf(assetVersionName, assetID, tag, defaultBranchName)
	} else {
		r0 = ret.Get(0).(models.AssetVersion)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, string, string) error); ok {
		r1 = rf(assetVersionName, assetID, tag, defaultBranchName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetVersionRepository_FindOrCreate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindOrCreate'
type CoreAssetVersionRepository_FindOrCreate_Call struct {
	*mock.Call
}

// FindOrCreate is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - tag string
//   - defaultBranchName string
func (_e *CoreAssetVersionRepository_Expecter) FindOrCreate(assetVersionName interface{}, assetID interface{}, tag interface{}, defaultBranchName interface{}) *CoreAssetVersionRepository_FindOrCreate_Call {
	return &CoreAssetVersionRepository_FindOrCreate_Call{Call: _e.mock.On("FindOrCreate", assetVersionName, assetID, tag, defaultBranchName)}
}

func (_c *CoreAssetVersionRepository_FindOrCreate_Call) Run(run func(assetVersionName string, assetID uuid.UUID, tag string, defaultBranchName string)) *CoreAssetVersionRepository_FindOrCreate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_FindOrCreate_Call) Return(_a0 models.AssetVersion, _a1 error) *CoreAssetVersionRepository_FindOrCreate_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionRepository_FindOrCreate_Call) RunAndReturn(run func(string, uuid.UUID, string, string) (models.AssetVersion, error)) *CoreAssetVersionRepository_FindOrCreate_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllAssetsVersionFromDBByAssetID provides a mock function with given fields: tx, assetID
func (_m *CoreAssetVersionRepository) GetAllAssetsVersionFromDBByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.AssetVersion, error) {
	ret := _m.Called(tx, assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllAssetsVersionFromDBByAssetID")
	}

	var r0 []models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) ([]models.AssetVersion, error)); ok {
		return rf(tx, assetID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) []models.AssetVersion); ok {
		r0 = rf(tx, assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetVersion)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID) error); ok {
		r1 = rf(tx, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllAssetsVersionFromDBByAssetID'
type CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call struct {
	*mock.Call
}

// GetAllAssetsVersionFromDBByAssetID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
func (_e *CoreAssetVersionRepository_Expecter) GetAllAssetsVersionFromDBByAssetID(tx interface{}, assetID interface{}) *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call {
	return &CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call{Call: _e.mock.On("GetAllAssetsVersionFromDBByAssetID", tx, assetID)}
}

func (_c *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID)) *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call) Return(_a0 []models.AssetVersion, _a1 error) *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.AssetVersion, error)) *CoreAssetVersionRepository_GetAllAssetsVersionFromDBByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: _a0
func (_m *CoreAssetVersionRepository) GetDB(_a0 *gorm.DB) *gorm.DB {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for GetDB")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func(*gorm.DB) *gorm.DB); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// CoreAssetVersionRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type CoreAssetVersionRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - _a0 *gorm.DB
func (_e *CoreAssetVersionRepository_Expecter) GetDB(_a0 interface{}) *CoreAssetVersionRepository_GetDB_Call {
	return &CoreAssetVersionRepository_GetDB_Call{Call: _e.mock.On("GetDB", _a0)}
}

func (_c *CoreAssetVersionRepository_GetDB_Call) Run(run func(_a0 *gorm.DB)) *CoreAssetVersionRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_GetDB_Call) Return(_a0 *gorm.DB) *CoreAssetVersionRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetVersionRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *CoreAssetVersionRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// GetDefaultAssetVersionsByProjectID provides a mock function with given fields: projectID
func (_m *CoreAssetVersionRepository) GetDefaultAssetVersionsByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetDefaultAssetVersionsByProjectID")
	}

	var r0 []models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.AssetVersion, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.AssetVersion); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetVersion)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDefaultAssetVersionsByProjectID'
type CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call struct {
	*mock.Call
}

// GetDefaultAssetVersionsByProjectID is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *CoreAssetVersionRepository_Expecter) GetDefaultAssetVersionsByProjectID(projectID interface{}) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call {
	return &CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call{Call: _e.mock.On("GetDefaultAssetVersionsByProjectID", projectID)}
}

func (_c *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call) Run(run func(projectID uuid.UUID)) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call) Return(_a0 []models.AssetVersion, _a1 error) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call) RunAndReturn(run func(uuid.UUID) ([]models.AssetVersion, error)) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectID_Call {
	_c.Call.Return(run)
	return _c
}

// GetDefaultAssetVersionsByProjectIDs provides a mock function with given fields: projectIDs
func (_m *CoreAssetVersionRepository) GetDefaultAssetVersionsByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error) {
	ret := _m.Called(projectIDs)

	if len(ret) == 0 {
		panic("no return value specified for GetDefaultAssetVersionsByProjectIDs")
	}

	var r0 []models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID) ([]models.AssetVersion, error)); ok {
		return rf(projectIDs)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID) []models.AssetVersion); ok {
		r0 = rf(projectIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetVersion)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = rf(projectIDs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDefaultAssetVersionsByProjectIDs'
type CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call struct {
	*mock.Call
}

// GetDefaultAssetVersionsByProjectIDs is a helper method to define mock.On call
//   - projectIDs []uuid.UUID
func (_e *CoreAssetVersionRepository_Expecter) GetDefaultAssetVersionsByProjectIDs(projectIDs interface{}) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call {
	return &CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call{Call: _e.mock.On("GetDefaultAssetVersionsByProjectIDs", projectIDs)}
}

func (_c *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call) Run(run func(projectIDs []uuid.UUID)) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call) Return(_a0 []models.AssetVersion, _a1 error) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call) RunAndReturn(run func([]uuid.UUID) ([]models.AssetVersion, error)) *CoreAssetVersionRepository_GetDefaultAssetVersionsByProjectIDs_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: assetVersionName, assetID
func (_m *CoreAssetVersionRepository) Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error) {
	ret := _m.Called(assetVersionName, assetID)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) (models.AssetVersion, error)); ok {
		return rf(assetVersionName, assetID)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID) models.AssetVersion); ok {
		r0 = rf(assetVersionName, assetID)
	} else {
		r0 = ret.Get(0).(models.AssetVersion)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID) error); ok {
		r1 = rf(assetVersionName, assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreAssetVersionRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type CoreAssetVersionRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
func (_e *CoreAssetVersionRepository_Expecter) Read(assetVersionName interface{}, assetID interface{}) *CoreAssetVersionRepository_Read_Call {
	return &CoreAssetVersionRepository_Read_Call{Call: _e.mock.On("Read", assetVersionName, assetID)}
}

func (_c *CoreAssetVersionRepository_Read_Call) Run(run func(assetVersionName string, assetID uuid.UUID)) *CoreAssetVersionRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_Read_Call) Return(_a0 models.AssetVersion, _a1 error) *CoreAssetVersionRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionRepository_Read_Call) RunAndReturn(run func(string, uuid.UUID) (models.AssetVersion, error)) *CoreAssetVersionRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, assetVersion
func (_m *CoreAssetVersionRepository) Save(tx *gorm.DB, assetVersion *models.AssetVersion) error {
	ret := _m.Called(tx, assetVersion)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.AssetVersion) error); ok {
		r0 = rf(tx, assetVersion)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreAssetVersionRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type CoreAssetVersionRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetVersion *models.AssetVersion
func (_e *CoreAssetVersionRepository_Expecter) Save(tx interface{}, assetVersion interface{}) *CoreAssetVersionRepository_Save_Call {
	return &CoreAssetVersionRepository_Save_Call{Call: _e.mock.On("Save", tx, assetVersion)}
}

func (_c *CoreAssetVersionRepository_Save_Call) Run(run func(tx *gorm.DB, assetVersion *models.AssetVersion)) *CoreAssetVersionRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.AssetVersion))
	})
	return _c
}

func (_c *CoreAssetVersionRepository_Save_Call) Return(_a0 error) *CoreAssetVersionRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetVersionRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.AssetVersion) error) *CoreAssetVersionRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreAssetVersionRepository creates a new instance of CoreAssetVersionRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreAssetVersionRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreAssetVersionRepository {
	mock := &CoreAssetVersionRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
