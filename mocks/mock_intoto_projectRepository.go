// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	uuid "github.com/google/uuid"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// IntotoProjectRepository is an autogenerated mock type for the projectRepository type
type IntotoProjectRepository struct {
	mock.Mock
}

type IntotoProjectRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntotoProjectRepository) EXPECT() *IntotoProjectRepository_Expecter {
	return &IntotoProjectRepository_Expecter{mock: &_m.Mock}
}

// GetProjectByAssetID provides a mock function with given fields: assetID
func (_m *IntotoProjectRepository) GetProjectByAssetID(assetID uuid.UUID) (models.Project, error) {
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

// IntotoProjectRepository_GetProjectByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjectByAssetID'
type IntotoProjectRepository_GetProjectByAssetID_Call struct {
	*mock.Call
}

// GetProjectByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *IntotoProjectRepository_Expecter) GetProjectByAssetID(assetID interface{}) *IntotoProjectRepository_GetProjectByAssetID_Call {
	return &IntotoProjectRepository_GetProjectByAssetID_Call{Call: _e.mock.On("GetProjectByAssetID", assetID)}
}

func (_c *IntotoProjectRepository_GetProjectByAssetID_Call) Run(run func(assetID uuid.UUID)) *IntotoProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *IntotoProjectRepository_GetProjectByAssetID_Call) Return(_a0 models.Project, _a1 error) *IntotoProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntotoProjectRepository_GetProjectByAssetID_Call) RunAndReturn(run func(uuid.UUID) (models.Project, error)) *IntotoProjectRepository_GetProjectByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntotoProjectRepository creates a new instance of IntotoProjectRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntotoProjectRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntotoProjectRepository {
	mock := &IntotoProjectRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
