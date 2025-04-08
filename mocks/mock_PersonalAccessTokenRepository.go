// Code generated by mockery v2.53.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// PersonalAccessTokenRepository is an autogenerated mock type for the PersonalAccessTokenRepository type
type PersonalAccessTokenRepository struct {
	mock.Mock
}

type PersonalAccessTokenRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *PersonalAccessTokenRepository) EXPECT() *PersonalAccessTokenRepository_Expecter {
	return &PersonalAccessTokenRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, id
func (_m *PersonalAccessTokenRepository) Activate(tx *gorm.DB, id uuid.UUID) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type PersonalAccessTokenRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) Activate(tx interface{}, id interface{}) *PersonalAccessTokenRepository_Activate_Call {
	return &PersonalAccessTokenRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *PersonalAccessTokenRepository_Activate_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *PersonalAccessTokenRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Activate_Call) Return(_a0 error) *PersonalAccessTokenRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *PersonalAccessTokenRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// All provides a mock function with no fields
func (_m *PersonalAccessTokenRepository) All() ([]models.PAT, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for All")
	}

	var r0 []models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]models.PAT, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []models.PAT); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PersonalAccessTokenRepository_All_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'All'
type PersonalAccessTokenRepository_All_Call struct {
	*mock.Call
}

// All is a helper method to define mock.On call
func (_e *PersonalAccessTokenRepository_Expecter) All() *PersonalAccessTokenRepository_All_Call {
	return &PersonalAccessTokenRepository_All_Call{Call: _e.mock.On("All")}
}

func (_c *PersonalAccessTokenRepository_All_Call) Run(run func()) *PersonalAccessTokenRepository_All_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_All_Call) Return(_a0 []models.PAT, _a1 error) *PersonalAccessTokenRepository_All_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PersonalAccessTokenRepository_All_Call) RunAndReturn(run func() ([]models.PAT, error)) *PersonalAccessTokenRepository_All_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function with no fields
func (_m *PersonalAccessTokenRepository) Begin() *gorm.DB {
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

// PersonalAccessTokenRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type PersonalAccessTokenRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *PersonalAccessTokenRepository_Expecter) Begin() *PersonalAccessTokenRepository_Begin_Call {
	return &PersonalAccessTokenRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *PersonalAccessTokenRepository_Begin_Call) Run(run func()) *PersonalAccessTokenRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Begin_Call) Return(_a0 *gorm.DB) *PersonalAccessTokenRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *PersonalAccessTokenRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, t
func (_m *PersonalAccessTokenRepository) Create(tx *gorm.DB, t *models.PAT) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.PAT) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type PersonalAccessTokenRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) Create(tx interface{}, t interface{}) *PersonalAccessTokenRepository_Create_Call {
	return &PersonalAccessTokenRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *PersonalAccessTokenRepository_Create_Call) Run(run func(tx *gorm.DB, t *models.PAT)) *PersonalAccessTokenRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.PAT))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Create_Call) Return(_a0 error) *PersonalAccessTokenRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.PAT) error) *PersonalAccessTokenRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *PersonalAccessTokenRepository) CreateBatch(tx *gorm.DB, ts []models.PAT) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.PAT) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type PersonalAccessTokenRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *PersonalAccessTokenRepository_CreateBatch_Call {
	return &PersonalAccessTokenRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *PersonalAccessTokenRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []models.PAT)) *PersonalAccessTokenRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.PAT))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_CreateBatch_Call) Return(_a0 error) *PersonalAccessTokenRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []models.PAT) error) *PersonalAccessTokenRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *PersonalAccessTokenRepository) Delete(tx *gorm.DB, id uuid.UUID) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type PersonalAccessTokenRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) Delete(tx interface{}, id interface{}) *PersonalAccessTokenRepository_Delete_Call {
	return &PersonalAccessTokenRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *PersonalAccessTokenRepository_Delete_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *PersonalAccessTokenRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Delete_Call) Return(_a0 error) *PersonalAccessTokenRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *PersonalAccessTokenRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteByFingerprint provides a mock function with given fields: fingerprint
func (_m *PersonalAccessTokenRepository) DeleteByFingerprint(fingerprint string) error {
	ret := _m.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for DeleteByFingerprint")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(fingerprint)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_DeleteByFingerprint_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteByFingerprint'
type PersonalAccessTokenRepository_DeleteByFingerprint_Call struct {
	*mock.Call
}

// DeleteByFingerprint is a helper method to define mock.On call
//   - fingerprint string
func (_e *PersonalAccessTokenRepository_Expecter) DeleteByFingerprint(fingerprint interface{}) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	return &PersonalAccessTokenRepository_DeleteByFingerprint_Call{Call: _e.mock.On("DeleteByFingerprint", fingerprint)}
}

func (_c *PersonalAccessTokenRepository_DeleteByFingerprint_Call) Run(run func(fingerprint string)) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_DeleteByFingerprint_Call) Return(_a0 error) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_DeleteByFingerprint_Call) RunAndReturn(run func(string) error) *PersonalAccessTokenRepository_DeleteByFingerprint_Call {
	_c.Call.Return(run)
	return _c
}

// FindByUserIDs provides a mock function with given fields: userID
func (_m *PersonalAccessTokenRepository) FindByUserIDs(userID []uuid.UUID) ([]models.PAT, error) {
	ret := _m.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for FindByUserIDs")
	}

	var r0 []models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID) ([]models.PAT, error)); ok {
		return rf(userID)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID) []models.PAT); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PersonalAccessTokenRepository_FindByUserIDs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByUserIDs'
type PersonalAccessTokenRepository_FindByUserIDs_Call struct {
	*mock.Call
}

// FindByUserIDs is a helper method to define mock.On call
//   - userID []uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) FindByUserIDs(userID interface{}) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	return &PersonalAccessTokenRepository_FindByUserIDs_Call{Call: _e.mock.On("FindByUserIDs", userID)}
}

func (_c *PersonalAccessTokenRepository_FindByUserIDs_Call) Run(run func(userID []uuid.UUID)) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_FindByUserIDs_Call) Return(_a0 []models.PAT, _a1 error) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PersonalAccessTokenRepository_FindByUserIDs_Call) RunAndReturn(run func([]uuid.UUID) ([]models.PAT, error)) *PersonalAccessTokenRepository_FindByUserIDs_Call {
	_c.Call.Return(run)
	return _c
}

// GetByFingerprint provides a mock function with given fields: fingerprint
func (_m *PersonalAccessTokenRepository) GetByFingerprint(fingerprint string) (models.PAT, error) {
	ret := _m.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for GetByFingerprint")
	}

	var r0 models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.PAT, error)); ok {
		return rf(fingerprint)
	}
	if rf, ok := ret.Get(0).(func(string) models.PAT); ok {
		r0 = rf(fingerprint)
	} else {
		r0 = ret.Get(0).(models.PAT)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(fingerprint)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PersonalAccessTokenRepository_GetByFingerprint_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByFingerprint'
type PersonalAccessTokenRepository_GetByFingerprint_Call struct {
	*mock.Call
}

// GetByFingerprint is a helper method to define mock.On call
//   - fingerprint string
func (_e *PersonalAccessTokenRepository_Expecter) GetByFingerprint(fingerprint interface{}) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	return &PersonalAccessTokenRepository_GetByFingerprint_Call{Call: _e.mock.On("GetByFingerprint", fingerprint)}
}

func (_c *PersonalAccessTokenRepository_GetByFingerprint_Call) Run(run func(fingerprint string)) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_GetByFingerprint_Call) Return(_a0 models.PAT, _a1 error) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PersonalAccessTokenRepository_GetByFingerprint_Call) RunAndReturn(run func(string) (models.PAT, error)) *PersonalAccessTokenRepository_GetByFingerprint_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *PersonalAccessTokenRepository) GetDB(tx *gorm.DB) *gorm.DB {
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

// PersonalAccessTokenRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type PersonalAccessTokenRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *PersonalAccessTokenRepository_Expecter) GetDB(tx interface{}) *PersonalAccessTokenRepository_GetDB_Call {
	return &PersonalAccessTokenRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *PersonalAccessTokenRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *PersonalAccessTokenRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_GetDB_Call) Return(_a0 *gorm.DB) *PersonalAccessTokenRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *PersonalAccessTokenRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *PersonalAccessTokenRepository) List(ids []uuid.UUID) ([]models.PAT, error) {
	ret := _m.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID) ([]models.PAT, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID) []models.PAT); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PersonalAccessTokenRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type PersonalAccessTokenRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) List(ids interface{}) *PersonalAccessTokenRepository_List_Call {
	return &PersonalAccessTokenRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *PersonalAccessTokenRepository_List_Call) Run(run func(ids []uuid.UUID)) *PersonalAccessTokenRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_List_Call) Return(_a0 []models.PAT, _a1 error) *PersonalAccessTokenRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PersonalAccessTokenRepository_List_Call) RunAndReturn(run func([]uuid.UUID) ([]models.PAT, error)) *PersonalAccessTokenRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// ListByUserID provides a mock function with given fields: userID
func (_m *PersonalAccessTokenRepository) ListByUserID(userID string) ([]models.PAT, error) {
	ret := _m.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for ListByUserID")
	}

	var r0 []models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]models.PAT, error)); ok {
		return rf(userID)
	}
	if rf, ok := ret.Get(0).(func(string) []models.PAT); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.PAT)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PersonalAccessTokenRepository_ListByUserID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListByUserID'
type PersonalAccessTokenRepository_ListByUserID_Call struct {
	*mock.Call
}

// ListByUserID is a helper method to define mock.On call
//   - userID string
func (_e *PersonalAccessTokenRepository_Expecter) ListByUserID(userID interface{}) *PersonalAccessTokenRepository_ListByUserID_Call {
	return &PersonalAccessTokenRepository_ListByUserID_Call{Call: _e.mock.On("ListByUserID", userID)}
}

func (_c *PersonalAccessTokenRepository_ListByUserID_Call) Run(run func(userID string)) *PersonalAccessTokenRepository_ListByUserID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_ListByUserID_Call) Return(_a0 []models.PAT, _a1 error) *PersonalAccessTokenRepository_ListByUserID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PersonalAccessTokenRepository_ListByUserID_Call) RunAndReturn(run func(string) ([]models.PAT, error)) *PersonalAccessTokenRepository_ListByUserID_Call {
	_c.Call.Return(run)
	return _c
}

// MarkAsLastUsedNow provides a mock function with given fields: fingerprint
func (_m *PersonalAccessTokenRepository) MarkAsLastUsedNow(fingerprint string) error {
	ret := _m.Called(fingerprint)

	if len(ret) == 0 {
		panic("no return value specified for MarkAsLastUsedNow")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(fingerprint)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_MarkAsLastUsedNow_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MarkAsLastUsedNow'
type PersonalAccessTokenRepository_MarkAsLastUsedNow_Call struct {
	*mock.Call
}

// MarkAsLastUsedNow is a helper method to define mock.On call
//   - fingerprint string
func (_e *PersonalAccessTokenRepository_Expecter) MarkAsLastUsedNow(fingerprint interface{}) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	return &PersonalAccessTokenRepository_MarkAsLastUsedNow_Call{Call: _e.mock.On("MarkAsLastUsedNow", fingerprint)}
}

func (_c *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call) Run(run func(fingerprint string)) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call) Return(_a0 error) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call) RunAndReturn(run func(string) error) *PersonalAccessTokenRepository_MarkAsLastUsedNow_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *PersonalAccessTokenRepository) Read(id uuid.UUID) (models.PAT, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.PAT, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.PAT); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.PAT)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PersonalAccessTokenRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type PersonalAccessTokenRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id uuid.UUID
func (_e *PersonalAccessTokenRepository_Expecter) Read(id interface{}) *PersonalAccessTokenRepository_Read_Call {
	return &PersonalAccessTokenRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *PersonalAccessTokenRepository_Read_Call) Run(run func(id uuid.UUID)) *PersonalAccessTokenRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Read_Call) Return(_a0 models.PAT, _a1 error) *PersonalAccessTokenRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PersonalAccessTokenRepository_Read_Call) RunAndReturn(run func(uuid.UUID) (models.PAT, error)) *PersonalAccessTokenRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *PersonalAccessTokenRepository) Save(tx *gorm.DB, t *models.PAT) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.PAT) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type PersonalAccessTokenRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) Save(tx interface{}, t interface{}) *PersonalAccessTokenRepository_Save_Call {
	return &PersonalAccessTokenRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *PersonalAccessTokenRepository_Save_Call) Run(run func(tx *gorm.DB, t *models.PAT)) *PersonalAccessTokenRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.PAT))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Save_Call) Return(_a0 error) *PersonalAccessTokenRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.PAT) error) *PersonalAccessTokenRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *PersonalAccessTokenRepository) SaveBatch(tx *gorm.DB, ts []models.PAT) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.PAT) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PersonalAccessTokenRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type PersonalAccessTokenRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.PAT
func (_e *PersonalAccessTokenRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *PersonalAccessTokenRepository_SaveBatch_Call {
	return &PersonalAccessTokenRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *PersonalAccessTokenRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []models.PAT)) *PersonalAccessTokenRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.PAT))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_SaveBatch_Call) Return(_a0 error) *PersonalAccessTokenRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.PAT) error) *PersonalAccessTokenRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *PersonalAccessTokenRepository) Transaction(_a0 func(*gorm.DB) error) error {
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

// PersonalAccessTokenRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type PersonalAccessTokenRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *PersonalAccessTokenRepository_Expecter) Transaction(_a0 interface{}) *PersonalAccessTokenRepository_Transaction_Call {
	return &PersonalAccessTokenRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *PersonalAccessTokenRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *PersonalAccessTokenRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *PersonalAccessTokenRepository_Transaction_Call) Return(_a0 error) *PersonalAccessTokenRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PersonalAccessTokenRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *PersonalAccessTokenRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewPersonalAccessTokenRepository creates a new instance of PersonalAccessTokenRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPersonalAccessTokenRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *PersonalAccessTokenRepository {
	mock := &PersonalAccessTokenRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
