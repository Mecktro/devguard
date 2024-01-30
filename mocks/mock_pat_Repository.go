// Code generated by mockery v2.40.1. DO NOT EDIT.

package mocks

import (
	pat "github.com/l3montree-dev/flawfix/internal/core/pat"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// PatRepository is an autogenerated mock type for the Repository type
type PatRepository struct {
	mock.Mock
}

type PatRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *PatRepository) EXPECT() *PatRepository_Expecter {
	return &PatRepository_Expecter{mock: &_m.Mock}
}

// Create provides a mock function with given fields: tx, t
func (_m *PatRepository) Create(tx *gorm.DB, t *pat.Model) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *pat.Model) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PatRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type PatRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *pat.Model
func (_e *PatRepository_Expecter) Create(tx interface{}, t interface{}) *PatRepository_Create_Call {
	return &PatRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *PatRepository_Create_Call) Run(run func(tx *gorm.DB, t *pat.Model)) *PatRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*pat.Model))
	})
	return _c
}

func (_c *PatRepository_Create_Call) Return(_a0 error) *PatRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *pat.Model) error) *PatRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *PatRepository) CreateBatch(tx *gorm.DB, ts []pat.Model) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []pat.Model) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PatRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type PatRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []pat.Model
func (_e *PatRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *PatRepository_CreateBatch_Call {
	return &PatRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *PatRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []pat.Model)) *PatRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]pat.Model))
	})
	return _c
}

func (_c *PatRepository_CreateBatch_Call) Return(_a0 error) *PatRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []pat.Model) error) *PatRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *PatRepository) Delete(tx *gorm.DB, id uuid.UUID) error {
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

// PatRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type PatRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *PatRepository_Expecter) Delete(tx interface{}, id interface{}) *PatRepository_Delete_Call {
	return &PatRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *PatRepository_Delete_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *PatRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *PatRepository_Delete_Call) Return(_a0 error) *PatRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *PatRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *PatRepository) GetDB(tx *gorm.DB) *gorm.DB {
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

// PatRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type PatRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *PatRepository_Expecter) GetDB(tx interface{}) *PatRepository_GetDB_Call {
	return &PatRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *PatRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *PatRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *PatRepository_GetDB_Call) Return(_a0 *gorm.DB) *PatRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *PatRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// GetUserIDByToken provides a mock function with given fields: token
func (_m *PatRepository) GetUserIDByToken(token string) (string, error) {
	ret := _m.Called(token)

	if len(ret) == 0 {
		panic("no return value specified for GetUserIDByToken")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(token)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PatRepository_GetUserIDByToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUserIDByToken'
type PatRepository_GetUserIDByToken_Call struct {
	*mock.Call
}

// GetUserIDByToken is a helper method to define mock.On call
//   - token string
func (_e *PatRepository_Expecter) GetUserIDByToken(token interface{}) *PatRepository_GetUserIDByToken_Call {
	return &PatRepository_GetUserIDByToken_Call{Call: _e.mock.On("GetUserIDByToken", token)}
}

func (_c *PatRepository_GetUserIDByToken_Call) Run(run func(token string)) *PatRepository_GetUserIDByToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PatRepository_GetUserIDByToken_Call) Return(_a0 string, _a1 error) *PatRepository_GetUserIDByToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PatRepository_GetUserIDByToken_Call) RunAndReturn(run func(string) (string, error)) *PatRepository_GetUserIDByToken_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *PatRepository) List(ids []uuid.UUID) ([]pat.Model, error) {
	ret := _m.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []pat.Model
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID) ([]pat.Model, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID) []pat.Model); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]pat.Model)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PatRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type PatRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []uuid.UUID
func (_e *PatRepository_Expecter) List(ids interface{}) *PatRepository_List_Call {
	return &PatRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *PatRepository_List_Call) Run(run func(ids []uuid.UUID)) *PatRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID))
	})
	return _c
}

func (_c *PatRepository_List_Call) Return(_a0 []pat.Model, _a1 error) *PatRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PatRepository_List_Call) RunAndReturn(run func([]uuid.UUID) ([]pat.Model, error)) *PatRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// ListByUserID provides a mock function with given fields: userId
func (_m *PatRepository) ListByUserID(userId string) ([]pat.Model, error) {
	ret := _m.Called(userId)

	if len(ret) == 0 {
		panic("no return value specified for ListByUserID")
	}

	var r0 []pat.Model
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]pat.Model, error)); ok {
		return rf(userId)
	}
	if rf, ok := ret.Get(0).(func(string) []pat.Model); ok {
		r0 = rf(userId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]pat.Model)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(userId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PatRepository_ListByUserID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListByUserID'
type PatRepository_ListByUserID_Call struct {
	*mock.Call
}

// ListByUserID is a helper method to define mock.On call
//   - userId string
func (_e *PatRepository_Expecter) ListByUserID(userId interface{}) *PatRepository_ListByUserID_Call {
	return &PatRepository_ListByUserID_Call{Call: _e.mock.On("ListByUserID", userId)}
}

func (_c *PatRepository_ListByUserID_Call) Run(run func(userId string)) *PatRepository_ListByUserID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PatRepository_ListByUserID_Call) Return(_a0 []pat.Model, _a1 error) *PatRepository_ListByUserID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PatRepository_ListByUserID_Call) RunAndReturn(run func(string) ([]pat.Model, error)) *PatRepository_ListByUserID_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *PatRepository) Read(id uuid.UUID) (pat.Model, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 pat.Model
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (pat.Model, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) pat.Model); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(pat.Model)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PatRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type PatRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id uuid.UUID
func (_e *PatRepository_Expecter) Read(id interface{}) *PatRepository_Read_Call {
	return &PatRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *PatRepository_Read_Call) Run(run func(id uuid.UUID)) *PatRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *PatRepository_Read_Call) Return(_a0 pat.Model, _a1 error) *PatRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PatRepository_Read_Call) RunAndReturn(run func(uuid.UUID) (pat.Model, error)) *PatRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// ReadByToken provides a mock function with given fields: token
func (_m *PatRepository) ReadByToken(token string) (pat.Model, error) {
	ret := _m.Called(token)

	if len(ret) == 0 {
		panic("no return value specified for ReadByToken")
	}

	var r0 pat.Model
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (pat.Model, error)); ok {
		return rf(token)
	}
	if rf, ok := ret.Get(0).(func(string) pat.Model); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Get(0).(pat.Model)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PatRepository_ReadByToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadByToken'
type PatRepository_ReadByToken_Call struct {
	*mock.Call
}

// ReadByToken is a helper method to define mock.On call
//   - token string
func (_e *PatRepository_Expecter) ReadByToken(token interface{}) *PatRepository_ReadByToken_Call {
	return &PatRepository_ReadByToken_Call{Call: _e.mock.On("ReadByToken", token)}
}

func (_c *PatRepository_ReadByToken_Call) Run(run func(token string)) *PatRepository_ReadByToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *PatRepository_ReadByToken_Call) Return(_a0 pat.Model, _a1 error) *PatRepository_ReadByToken_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *PatRepository_ReadByToken_Call) RunAndReturn(run func(string) (pat.Model, error)) *PatRepository_ReadByToken_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *PatRepository) Save(tx *gorm.DB, t *pat.Model) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *pat.Model) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PatRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type PatRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *pat.Model
func (_e *PatRepository_Expecter) Save(tx interface{}, t interface{}) *PatRepository_Save_Call {
	return &PatRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *PatRepository_Save_Call) Run(run func(tx *gorm.DB, t *pat.Model)) *PatRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*pat.Model))
	})
	return _c
}

func (_c *PatRepository_Save_Call) Return(_a0 error) *PatRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *pat.Model) error) *PatRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *PatRepository) SaveBatch(tx *gorm.DB, ts []pat.Model) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []pat.Model) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PatRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type PatRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []pat.Model
func (_e *PatRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *PatRepository_SaveBatch_Call {
	return &PatRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *PatRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []pat.Model)) *PatRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]pat.Model))
	})
	return _c
}

func (_c *PatRepository_SaveBatch_Call) Return(_a0 error) *PatRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []pat.Model) error) *PatRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *PatRepository) Transaction(_a0 func(*gorm.DB) error) error {
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

// PatRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type PatRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *PatRepository_Expecter) Transaction(_a0 interface{}) *PatRepository_Transaction_Call {
	return &PatRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *PatRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *PatRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *PatRepository_Transaction_Call) Return(_a0 error) *PatRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *PatRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: tx, t
func (_m *PatRepository) Update(tx *gorm.DB, t *pat.Model) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *pat.Model) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PatRepository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type PatRepository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *pat.Model
func (_e *PatRepository_Expecter) Update(tx interface{}, t interface{}) *PatRepository_Update_Call {
	return &PatRepository_Update_Call{Call: _e.mock.On("Update", tx, t)}
}

func (_c *PatRepository_Update_Call) Run(run func(tx *gorm.DB, t *pat.Model)) *PatRepository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*pat.Model))
	})
	return _c
}

func (_c *PatRepository_Update_Call) Return(_a0 error) *PatRepository_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_Update_Call) RunAndReturn(run func(*gorm.DB, *pat.Model) error) *PatRepository_Update_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateBatch provides a mock function with given fields: tx, ts
func (_m *PatRepository) UpdateBatch(tx *gorm.DB, ts []pat.Model) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for UpdateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []pat.Model) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PatRepository_UpdateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateBatch'
type PatRepository_UpdateBatch_Call struct {
	*mock.Call
}

// UpdateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []pat.Model
func (_e *PatRepository_Expecter) UpdateBatch(tx interface{}, ts interface{}) *PatRepository_UpdateBatch_Call {
	return &PatRepository_UpdateBatch_Call{Call: _e.mock.On("UpdateBatch", tx, ts)}
}

func (_c *PatRepository_UpdateBatch_Call) Run(run func(tx *gorm.DB, ts []pat.Model)) *PatRepository_UpdateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]pat.Model))
	})
	return _c
}

func (_c *PatRepository_UpdateBatch_Call) Return(_a0 error) *PatRepository_UpdateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *PatRepository_UpdateBatch_Call) RunAndReturn(run func(*gorm.DB, []pat.Model) error) *PatRepository_UpdateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewPatRepository creates a new instance of PatRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPatRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *PatRepository {
	mock := &PatRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
