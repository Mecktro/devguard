// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// StatisticsProjectRepository is an autogenerated mock type for the projectRepository type
type StatisticsProjectRepository struct {
	mock.Mock
}

type StatisticsProjectRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsProjectRepository) EXPECT() *StatisticsProjectRepository_Expecter {
	return &StatisticsProjectRepository_Expecter{mock: &_m.Mock}
}

// GetProjectByAssetID provides a mock function with given fields: assetID
func (_m *StatisticsProjectRepository) GetProjectByAssetID(assetID uuid.UUID) (models.Project, error) {
	ret := _m.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectByAssetID")
	}

	var r0 models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.Project, error)); ok {
		return rf(assetID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.Project); ok {
		r0 = rf(assetID)
	} else {
		r0 = ret.Get(0).(models.Project)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsProjectRepository_GetProjectByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjectByAssetID'
type StatisticsProjectRepository_GetProjectByAssetID_Call struct {
	*mock.Call
}

// GetProjectByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *StatisticsProjectRepository_Expecter) GetProjectByAssetID(assetID interface{}) *StatisticsProjectRepository_GetProjectByAssetID_Call {
	return &StatisticsProjectRepository_GetProjectByAssetID_Call{Call: _e.mock.On("GetProjectByAssetID", assetID)}
}

func (_c *StatisticsProjectRepository_GetProjectByAssetID_Call) Run(run func(assetID uuid.UUID)) *StatisticsProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsProjectRepository_GetProjectByAssetID_Call) Return(_a0 models.Project, _a1 error) *StatisticsProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsProjectRepository_GetProjectByAssetID_Call) RunAndReturn(run func(uuid.UUID) (models.Project, error)) *StatisticsProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *StatisticsProjectRepository) Read(id uuid.UUID) (models.Project, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.Project, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.Project); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.Project)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsProjectRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type StatisticsProjectRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id uuid.UUID
func (_e *StatisticsProjectRepository_Expecter) Read(id interface{}) *StatisticsProjectRepository_Read_Call {
	return &StatisticsProjectRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *StatisticsProjectRepository_Read_Call) Run(run func(id uuid.UUID)) *StatisticsProjectRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsProjectRepository_Read_Call) Return(_a0 models.Project, _a1 error) *StatisticsProjectRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsProjectRepository_Read_Call) RunAndReturn(run func(uuid.UUID) (models.Project, error)) *StatisticsProjectRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// RecursivelyGetChildProjects provides a mock function with given fields: projectID
func (_m *StatisticsProjectRepository) RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for RecursivelyGetChildProjects")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsProjectRepository_RecursivelyGetChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecursivelyGetChildProjects'
type StatisticsProjectRepository_RecursivelyGetChildProjects_Call struct {
	*mock.Call
}

// RecursivelyGetChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *StatisticsProjectRepository_Expecter) RecursivelyGetChildProjects(projectID interface{}) *StatisticsProjectRepository_RecursivelyGetChildProjects_Call {
	return &StatisticsProjectRepository_RecursivelyGetChildProjects_Call{Call: _e.mock.On("RecursivelyGetChildProjects", projectID)}
}

func (_c *StatisticsProjectRepository_RecursivelyGetChildProjects_Call) Run(run func(projectID uuid.UUID)) *StatisticsProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsProjectRepository_RecursivelyGetChildProjects_Call) Return(_a0 []models.Project, _a1 error) *StatisticsProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsProjectRepository_RecursivelyGetChildProjects_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *StatisticsProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsProjectRepository creates a new instance of StatisticsProjectRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsProjectRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsProjectRepository {
	mock := &StatisticsProjectRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
