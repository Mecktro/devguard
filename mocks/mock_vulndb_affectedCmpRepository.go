// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	database "github.com/l3montree-dev/devguard/internal/database"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// VulndbAffectedCmpRepository is an autogenerated mock type for the affectedCmpRepository type
type VulndbAffectedCmpRepository struct {
	mock.Mock
}

type VulndbAffectedCmpRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *VulndbAffectedCmpRepository) EXPECT() *VulndbAffectedCmpRepository_Expecter {
	return &VulndbAffectedCmpRepository_Expecter{mock: &_m.Mock}
}

// SaveBatch provides a mock function with given fields: tx, affectedComponents
func (_m *VulndbAffectedCmpRepository) SaveBatch(tx database.DB, affectedComponents []models.AffectedComponent) error {
	ret := _m.Called(tx, affectedComponents)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(database.DB, []models.AffectedComponent) error); ok {
		r0 = rf(tx, affectedComponents)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VulndbAffectedCmpRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type VulndbAffectedCmpRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx database.DB
//   - affectedComponents []models.AffectedComponent
func (_e *VulndbAffectedCmpRepository_Expecter) SaveBatch(tx interface{}, affectedComponents interface{}) *VulndbAffectedCmpRepository_SaveBatch_Call {
	return &VulndbAffectedCmpRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, affectedComponents)}
}

func (_c *VulndbAffectedCmpRepository_SaveBatch_Call) Run(run func(tx database.DB, affectedComponents []models.AffectedComponent)) *VulndbAffectedCmpRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(database.DB), args[1].([]models.AffectedComponent))
	})
	return _c
}

func (_c *VulndbAffectedCmpRepository_SaveBatch_Call) Return(_a0 error) *VulndbAffectedCmpRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *VulndbAffectedCmpRepository_SaveBatch_Call) RunAndReturn(run func(database.DB, []models.AffectedComponent) error) *VulndbAffectedCmpRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewVulndbAffectedCmpRepository creates a new instance of VulndbAffectedCmpRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewVulndbAffectedCmpRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *VulndbAffectedCmpRepository {
	mock := &VulndbAffectedCmpRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
