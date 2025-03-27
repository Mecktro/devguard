// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// CoreVulnRepository is an autogenerated mock type for the VulnRepository type
type CoreVulnRepository struct {
	mock.Mock
}

type CoreVulnRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreVulnRepository) EXPECT() *CoreVulnRepository_Expecter {
	return &CoreVulnRepository_Expecter{mock: &_m.Mock}
}

// FindByTicketID provides a mock function with given fields: tx, ticketID
func (_m *CoreVulnRepository) FindByTicketID(tx *gorm.DB, ticketID string) (models.Vuln, error) {
	ret := _m.Called(tx, ticketID)

	if len(ret) == 0 {
		panic("no return value specified for FindByTicketID")
	}

	var r0 models.Vuln
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) (models.Vuln, error)); ok {
		return rf(tx, ticketID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) models.Vuln); ok {
		r0 = rf(tx, ticketID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(models.Vuln)
		}
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string) error); ok {
		r1 = rf(tx, ticketID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreVulnRepository_FindByTicketID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByTicketID'
type CoreVulnRepository_FindByTicketID_Call struct {
	*mock.Call
}

// FindByTicketID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ticketID string
func (_e *CoreVulnRepository_Expecter) FindByTicketID(tx interface{}, ticketID interface{}) *CoreVulnRepository_FindByTicketID_Call {
	return &CoreVulnRepository_FindByTicketID_Call{Call: _e.mock.On("FindByTicketID", tx, ticketID)}
}

func (_c *CoreVulnRepository_FindByTicketID_Call) Run(run func(tx *gorm.DB, ticketID string)) *CoreVulnRepository_FindByTicketID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *CoreVulnRepository_FindByTicketID_Call) Return(_a0 models.Vuln, _a1 error) *CoreVulnRepository_FindByTicketID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreVulnRepository_FindByTicketID_Call) RunAndReturn(run func(*gorm.DB, string) (models.Vuln, error)) *CoreVulnRepository_FindByTicketID_Call {
	_c.Call.Return(run)
	return _c
}

// GetOrgFromVuln provides a mock function with given fields: vuln
func (_m *CoreVulnRepository) GetOrgFromVuln(vuln models.Vuln) (models.Org, error) {
	ret := _m.Called(vuln)

	if len(ret) == 0 {
		panic("no return value specified for GetOrgFromVuln")
	}

	var r0 models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func(models.Vuln) (models.Org, error)); ok {
		return rf(vuln)
	}
	if rf, ok := ret.Get(0).(func(models.Vuln) models.Org); ok {
		r0 = rf(vuln)
	} else {
		r0 = ret.Get(0).(models.Org)
	}

	if rf, ok := ret.Get(1).(func(models.Vuln) error); ok {
		r1 = rf(vuln)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreVulnRepository_GetOrgFromVuln_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOrgFromVuln'
type CoreVulnRepository_GetOrgFromVuln_Call struct {
	*mock.Call
}

// GetOrgFromVuln is a helper method to define mock.On call
//   - vuln models.Vuln
func (_e *CoreVulnRepository_Expecter) GetOrgFromVuln(vuln interface{}) *CoreVulnRepository_GetOrgFromVuln_Call {
	return &CoreVulnRepository_GetOrgFromVuln_Call{Call: _e.mock.On("GetOrgFromVuln", vuln)}
}

func (_c *CoreVulnRepository_GetOrgFromVuln_Call) Run(run func(vuln models.Vuln)) *CoreVulnRepository_GetOrgFromVuln_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Vuln))
	})
	return _c
}

func (_c *CoreVulnRepository_GetOrgFromVuln_Call) Return(_a0 models.Org, _a1 error) *CoreVulnRepository_GetOrgFromVuln_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreVulnRepository_GetOrgFromVuln_Call) RunAndReturn(run func(models.Vuln) (models.Org, error)) *CoreVulnRepository_GetOrgFromVuln_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: db, vuln
func (_m *CoreVulnRepository) Save(db *gorm.DB, vuln *models.Vuln) error {
	ret := _m.Called(db, vuln)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Vuln) error); ok {
		r0 = rf(db, vuln)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreVulnRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type CoreVulnRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - vuln *models.Vuln
func (_e *CoreVulnRepository_Expecter) Save(db interface{}, vuln interface{}) *CoreVulnRepository_Save_Call {
	return &CoreVulnRepository_Save_Call{Call: _e.mock.On("Save", db, vuln)}
}

func (_c *CoreVulnRepository_Save_Call) Run(run func(db *gorm.DB, vuln *models.Vuln)) *CoreVulnRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Vuln))
	})
	return _c
}

func (_c *CoreVulnRepository_Save_Call) Return(_a0 error) *CoreVulnRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreVulnRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Vuln) error) *CoreVulnRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: fn
func (_m *CoreVulnRepository) Transaction(fn func(*gorm.DB) error) error {
	ret := _m.Called(fn)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(*gorm.DB) error) error); ok {
		r0 = rf(fn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreVulnRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type CoreVulnRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - fn func(*gorm.DB) error
func (_e *CoreVulnRepository_Expecter) Transaction(fn interface{}) *CoreVulnRepository_Transaction_Call {
	return &CoreVulnRepository_Transaction_Call{Call: _e.mock.On("Transaction", fn)}
}

func (_c *CoreVulnRepository_Transaction_Call) Run(run func(fn func(*gorm.DB) error)) *CoreVulnRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *CoreVulnRepository_Transaction_Call) Return(_a0 error) *CoreVulnRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreVulnRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *CoreVulnRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreVulnRepository creates a new instance of CoreVulnRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreVulnRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreVulnRepository {
	mock := &CoreVulnRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
