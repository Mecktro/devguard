// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	core "github.com/l3montree-dev/devguard/internal/core"

	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// DependencyVulnRepository is an autogenerated mock type for the repository type
type DependencyVulnRepository struct {
	mock.Mock
}

type DependencyVulnRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *DependencyVulnRepository) EXPECT() *DependencyVulnRepository_Expecter {
	return &DependencyVulnRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, id
func (_m *DependencyVulnRepository) Activate(tx *gorm.DB, id string) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type DependencyVulnRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *DependencyVulnRepository_Expecter) Activate(tx interface{}, id interface{}) *DependencyVulnRepository_Activate_Call {
	return &DependencyVulnRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *DependencyVulnRepository_Activate_Call) Run(run func(tx *gorm.DB, id string)) *DependencyVulnRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *DependencyVulnRepository_Activate_Call) Return(_a0 error) *DependencyVulnRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, string) error) *DependencyVulnRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function with no fields
func (_m *DependencyVulnRepository) Begin() *gorm.DB {
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

// DependencyVulnRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type DependencyVulnRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *DependencyVulnRepository_Expecter) Begin() *DependencyVulnRepository_Begin_Call {
	return &DependencyVulnRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *DependencyVulnRepository_Begin_Call) Run(run func()) *DependencyVulnRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *DependencyVulnRepository_Begin_Call) Return(_a0 *gorm.DB) *DependencyVulnRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *DependencyVulnRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, t
func (_m *DependencyVulnRepository) Create(tx *gorm.DB, t *models.DependencyVuln) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.DependencyVuln) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type DependencyVulnRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.DependencyVuln
func (_e *DependencyVulnRepository_Expecter) Create(tx interface{}, t interface{}) *DependencyVulnRepository_Create_Call {
	return &DependencyVulnRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *DependencyVulnRepository_Create_Call) Run(run func(tx *gorm.DB, t *models.DependencyVuln)) *DependencyVulnRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.DependencyVuln))
	})
	return _c
}

func (_c *DependencyVulnRepository_Create_Call) Return(_a0 error) *DependencyVulnRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.DependencyVuln) error) *DependencyVulnRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *DependencyVulnRepository) CreateBatch(tx *gorm.DB, ts []models.DependencyVuln) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.DependencyVuln) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type DependencyVulnRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.DependencyVuln
func (_e *DependencyVulnRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *DependencyVulnRepository_CreateBatch_Call {
	return &DependencyVulnRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *DependencyVulnRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []models.DependencyVuln)) *DependencyVulnRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.DependencyVuln))
	})
	return _c
}

func (_c *DependencyVulnRepository_CreateBatch_Call) Return(_a0 error) *DependencyVulnRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []models.DependencyVuln) error) *DependencyVulnRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *DependencyVulnRepository) Delete(tx *gorm.DB, id string) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type DependencyVulnRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *DependencyVulnRepository_Expecter) Delete(tx interface{}, id interface{}) *DependencyVulnRepository_Delete_Call {
	return &DependencyVulnRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *DependencyVulnRepository_Delete_Call) Run(run func(tx *gorm.DB, id string)) *DependencyVulnRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *DependencyVulnRepository_Delete_Call) Return(_a0 error) *DependencyVulnRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, string) error) *DependencyVulnRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetByAssetId provides a mock function with given fields: tx, assetId
func (_m *DependencyVulnRepository) GetByAssetId(tx *gorm.DB, assetId uuid.UUID) ([]models.DependencyVuln, error) {
	ret := _m.Called(tx, assetId)

	if len(ret) == 0 {
		panic("no return value specified for GetByAssetId")
	}

	var r0 []models.DependencyVuln
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) ([]models.DependencyVuln, error)); ok {
		return rf(tx, assetId)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) []models.DependencyVuln); ok {
		r0 = rf(tx, assetId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVuln)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID) error); ok {
		r1 = rf(tx, assetId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnRepository_GetByAssetId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByAssetId'
type DependencyVulnRepository_GetByAssetId_Call struct {
	*mock.Call
}

// GetByAssetId is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetId uuid.UUID
func (_e *DependencyVulnRepository_Expecter) GetByAssetId(tx interface{}, assetId interface{}) *DependencyVulnRepository_GetByAssetId_Call {
	return &DependencyVulnRepository_GetByAssetId_Call{Call: _e.mock.On("GetByAssetId", tx, assetId)}
}

func (_c *DependencyVulnRepository_GetByAssetId_Call) Run(run func(tx *gorm.DB, assetId uuid.UUID)) *DependencyVulnRepository_GetByAssetId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *DependencyVulnRepository_GetByAssetId_Call) Return(_a0 []models.DependencyVuln, _a1 error) *DependencyVulnRepository_GetByAssetId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnRepository_GetByAssetId_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) ([]models.DependencyVuln, error)) *DependencyVulnRepository_GetByAssetId_Call {
	_c.Call.Return(run)
	return _c
}

// GetByAssetIdPaged provides a mock function with given fields: tx, pageInfo, search, filter, sort, assetId
func (_m *DependencyVulnRepository) GetByAssetIdPaged(tx *gorm.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.DependencyVuln], map[string]int, error) {
	ret := _m.Called(tx, pageInfo, search, filter, sort, assetId)

	if len(ret) == 0 {
		panic("no return value specified for GetByAssetIdPaged")
	}

	var r0 core.Paged[models.DependencyVuln]
	var r1 map[string]int
	var r2 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) (core.Paged[models.DependencyVuln], map[string]int, error)); ok {
		return rf(tx, pageInfo, search, filter, sort, assetId)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) core.Paged[models.DependencyVuln]); ok {
		r0 = rf(tx, pageInfo, search, filter, sort, assetId)
	} else {
		r0 = ret.Get(0).(core.Paged[models.DependencyVuln])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) map[string]int); ok {
		r1 = rf(tx, pageInfo, search, filter, sort, assetId)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(map[string]int)
		}
	}

	if rf, ok := ret.Get(2).(func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) error); ok {
		r2 = rf(tx, pageInfo, search, filter, sort, assetId)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// DependencyVulnRepository_GetByAssetIdPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByAssetIdPaged'
type DependencyVulnRepository_GetByAssetIdPaged_Call struct {
	*mock.Call
}

// GetByAssetIdPaged is a helper method to define mock.On call
//   - tx *gorm.DB
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
//   - assetId uuid.UUID
func (_e *DependencyVulnRepository_Expecter) GetByAssetIdPaged(tx interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}, assetId interface{}) *DependencyVulnRepository_GetByAssetIdPaged_Call {
	return &DependencyVulnRepository_GetByAssetIdPaged_Call{Call: _e.mock.On("GetByAssetIdPaged", tx, pageInfo, search, filter, sort, assetId)}
}

func (_c *DependencyVulnRepository_GetByAssetIdPaged_Call) Run(run func(tx *gorm.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID)) *DependencyVulnRepository_GetByAssetIdPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(core.PageInfo), args[2].(string), args[3].([]core.FilterQuery), args[4].([]core.SortQuery), args[5].(uuid.UUID))
	})
	return _c
}

func (_c *DependencyVulnRepository_GetByAssetIdPaged_Call) Return(_a0 core.Paged[models.DependencyVuln], _a1 map[string]int, _a2 error) *DependencyVulnRepository_GetByAssetIdPaged_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *DependencyVulnRepository_GetByAssetIdPaged_Call) RunAndReturn(run func(*gorm.DB, core.PageInfo, string, []core.FilterQuery, []core.SortQuery, uuid.UUID) (core.Paged[models.DependencyVuln], map[string]int, error)) *DependencyVulnRepository_GetByAssetIdPaged_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *DependencyVulnRepository) GetDB(tx *gorm.DB) *gorm.DB {
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

// DependencyVulnRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type DependencyVulnRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *DependencyVulnRepository_Expecter) GetDB(tx interface{}) *DependencyVulnRepository_GetDB_Call {
	return &DependencyVulnRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *DependencyVulnRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *DependencyVulnRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *DependencyVulnRepository_GetDB_Call) Return(_a0 *gorm.DB) *DependencyVulnRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *DependencyVulnRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnsByAssetIdPagedAndFlat provides a mock function with given fields: tx, assetId, pageInfo, search, filter, sort
func (_m *DependencyVulnRepository) GetDependencyVulnsByAssetIdPagedAndFlat(tx *gorm.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	ret := _m.Called(tx, assetId, pageInfo, search, filter, sort)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnsByAssetIdPagedAndFlat")
	}

	var r0 core.Paged[models.DependencyVuln]
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.DependencyVuln], error)); ok {
		return rf(tx, assetId, pageInfo, search, filter, sort)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) core.Paged[models.DependencyVuln]); ok {
		r0 = rf(tx, assetId, pageInfo, search, filter, sort)
	} else {
		r0 = ret.Get(0).(core.Paged[models.DependencyVuln])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) error); ok {
		r1 = rf(tx, assetId, pageInfo, search, filter, sort)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnsByAssetIdPagedAndFlat'
type DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call struct {
	*mock.Call
}

// GetDependencyVulnsByAssetIdPagedAndFlat is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetId uuid.UUID
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
func (_e *DependencyVulnRepository_Expecter) GetDependencyVulnsByAssetIdPagedAndFlat(tx interface{}, assetId interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}) *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call {
	return &DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call{Call: _e.mock.On("GetDependencyVulnsByAssetIdPagedAndFlat", tx, assetId, pageInfo, search, filter, sort)}
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call) Run(run func(tx *gorm.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery)) *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(core.PageInfo), args[3].(string), args[4].([]core.FilterQuery), args[5].([]core.SortQuery))
	})
	return _c
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call) Return(_a0 core.Paged[models.DependencyVuln], _a1 error) *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.DependencyVuln], error)) *DependencyVulnRepository_GetDependencyVulnsByAssetIdPagedAndFlat_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnsByOrgIdPaged provides a mock function with given fields: tx, userAllowedProjectIds, pageInfo, search, filter, sort
func (_m *DependencyVulnRepository) GetDependencyVulnsByOrgIdPaged(tx *gorm.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	ret := _m.Called(tx, userAllowedProjectIds, pageInfo, search, filter, sort)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnsByOrgIdPaged")
	}

	var r0 core.Paged[models.DependencyVuln]
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.DependencyVuln], error)); ok {
		return rf(tx, userAllowedProjectIds, pageInfo, search, filter, sort)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) core.Paged[models.DependencyVuln]); ok {
		r0 = rf(tx, userAllowedProjectIds, pageInfo, search, filter, sort)
	} else {
		r0 = ret.Get(0).(core.Paged[models.DependencyVuln])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) error); ok {
		r1 = rf(tx, userAllowedProjectIds, pageInfo, search, filter, sort)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnsByOrgIdPaged'
type DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call struct {
	*mock.Call
}

// GetDependencyVulnsByOrgIdPaged is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userAllowedProjectIds []string
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
func (_e *DependencyVulnRepository_Expecter) GetDependencyVulnsByOrgIdPaged(tx interface{}, userAllowedProjectIds interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}) *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call {
	return &DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call{Call: _e.mock.On("GetDependencyVulnsByOrgIdPaged", tx, userAllowedProjectIds, pageInfo, search, filter, sort)}
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call) Run(run func(tx *gorm.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery)) *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]string), args[2].(core.PageInfo), args[3].(string), args[4].([]core.FilterQuery), args[5].([]core.SortQuery))
	})
	return _c
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call) Return(_a0 core.Paged[models.DependencyVuln], _a1 error) *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call) RunAndReturn(run func(*gorm.DB, []string, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.DependencyVuln], error)) *DependencyVulnRepository_GetDependencyVulnsByOrgIdPaged_Call {
	_c.Call.Return(run)
	return _c
}

// GetDependencyVulnsByProjectIdPaged provides a mock function with given fields: tx, projectID, pageInfo, search, filter, sort
func (_m *DependencyVulnRepository) GetDependencyVulnsByProjectIdPaged(tx *gorm.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	ret := _m.Called(tx, projectID, pageInfo, search, filter, sort)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyVulnsByProjectIdPaged")
	}

	var r0 core.Paged[models.DependencyVuln]
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.DependencyVuln], error)); ok {
		return rf(tx, projectID, pageInfo, search, filter, sort)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) core.Paged[models.DependencyVuln]); ok {
		r0 = rf(tx, projectID, pageInfo, search, filter, sort)
	} else {
		r0 = ret.Get(0).(core.Paged[models.DependencyVuln])
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) error); ok {
		r1 = rf(tx, projectID, pageInfo, search, filter, sort)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyVulnsByProjectIdPaged'
type DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call struct {
	*mock.Call
}

// GetDependencyVulnsByProjectIdPaged is a helper method to define mock.On call
//   - tx *gorm.DB
//   - projectID uuid.UUID
//   - pageInfo core.PageInfo
//   - search string
//   - filter []core.FilterQuery
//   - sort []core.SortQuery
func (_e *DependencyVulnRepository_Expecter) GetDependencyVulnsByProjectIdPaged(tx interface{}, projectID interface{}, pageInfo interface{}, search interface{}, filter interface{}, sort interface{}) *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call {
	return &DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call{Call: _e.mock.On("GetDependencyVulnsByProjectIdPaged", tx, projectID, pageInfo, search, filter, sort)}
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call) Run(run func(tx *gorm.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery)) *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(core.PageInfo), args[3].(string), args[4].([]core.FilterQuery), args[5].([]core.SortQuery))
	})
	return _c
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call) Return(_a0 core.Paged[models.DependencyVuln], _a1 error) *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, core.PageInfo, string, []core.FilterQuery, []core.SortQuery) (core.Paged[models.DependencyVuln], error)) *DependencyVulnRepository_GetDependencyVulnsByProjectIdPaged_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *DependencyVulnRepository) List(ids []string) ([]models.DependencyVuln, error) {
	ret := _m.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.DependencyVuln
	var r1 error
	if rf, ok := ret.Get(0).(func([]string) ([]models.DependencyVuln, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]string) []models.DependencyVuln); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.DependencyVuln)
		}
	}

	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type DependencyVulnRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []string
func (_e *DependencyVulnRepository_Expecter) List(ids interface{}) *DependencyVulnRepository_List_Call {
	return &DependencyVulnRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *DependencyVulnRepository_List_Call) Run(run func(ids []string)) *DependencyVulnRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]string))
	})
	return _c
}

func (_c *DependencyVulnRepository_List_Call) Return(_a0 []models.DependencyVuln, _a1 error) *DependencyVulnRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnRepository_List_Call) RunAndReturn(run func([]string) ([]models.DependencyVuln, error)) *DependencyVulnRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *DependencyVulnRepository) Read(id string) (models.DependencyVuln, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.DependencyVuln
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.DependencyVuln, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(string) models.DependencyVuln); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.DependencyVuln)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type DependencyVulnRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id string
func (_e *DependencyVulnRepository_Expecter) Read(id interface{}) *DependencyVulnRepository_Read_Call {
	return &DependencyVulnRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *DependencyVulnRepository_Read_Call) Run(run func(id string)) *DependencyVulnRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *DependencyVulnRepository_Read_Call) Return(_a0 models.DependencyVuln, _a1 error) *DependencyVulnRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnRepository_Read_Call) RunAndReturn(run func(string) (models.DependencyVuln, error)) *DependencyVulnRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *DependencyVulnRepository) Save(tx *gorm.DB, t *models.DependencyVuln) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.DependencyVuln) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type DependencyVulnRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.DependencyVuln
func (_e *DependencyVulnRepository_Expecter) Save(tx interface{}, t interface{}) *DependencyVulnRepository_Save_Call {
	return &DependencyVulnRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *DependencyVulnRepository_Save_Call) Run(run func(tx *gorm.DB, t *models.DependencyVuln)) *DependencyVulnRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.DependencyVuln))
	})
	return _c
}

func (_c *DependencyVulnRepository_Save_Call) Return(_a0 error) *DependencyVulnRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.DependencyVuln) error) *DependencyVulnRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *DependencyVulnRepository) SaveBatch(tx *gorm.DB, ts []models.DependencyVuln) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.DependencyVuln) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type DependencyVulnRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.DependencyVuln
func (_e *DependencyVulnRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *DependencyVulnRepository_SaveBatch_Call {
	return &DependencyVulnRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *DependencyVulnRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []models.DependencyVuln)) *DependencyVulnRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.DependencyVuln))
	})
	return _c
}

func (_c *DependencyVulnRepository_SaveBatch_Call) Return(_a0 error) *DependencyVulnRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.DependencyVuln) error) *DependencyVulnRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *DependencyVulnRepository) Transaction(_a0 func(*gorm.DB) error) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(*gorm.DB) error) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type DependencyVulnRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *DependencyVulnRepository_Expecter) Transaction(_a0 interface{}) *DependencyVulnRepository_Transaction_Call {
	return &DependencyVulnRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *DependencyVulnRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *DependencyVulnRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *DependencyVulnRepository_Transaction_Call) Return(_a0 error) *DependencyVulnRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *DependencyVulnRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewDependencyVulnRepository creates a new instance of DependencyVulnRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDependencyVulnRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *DependencyVulnRepository {
	mock := &DependencyVulnRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
