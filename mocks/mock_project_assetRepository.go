// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// ProjectAssetRepository is an autogenerated mock type for the assetRepository type
type ProjectAssetRepository struct {
	mock.Mock
}

type ProjectAssetRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ProjectAssetRepository) EXPECT() *ProjectAssetRepository_Expecter {
	return &ProjectAssetRepository_Expecter{mock: &_m.Mock}
}

// GetByProjectID provides a mock function with given fields: projectID
func (_m *ProjectAssetRepository) GetByProjectID(projectID uuid.UUID) ([]models.Asset, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetByProjectID")
	}

	var r0 []models.Asset
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.Asset, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.Asset); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Asset)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectAssetRepository_GetByProjectID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByProjectID'
type ProjectAssetRepository_GetByProjectID_Call struct {
	*mock.Call
}

// GetByProjectID is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectAssetRepository_Expecter) GetByProjectID(projectID interface{}) *ProjectAssetRepository_GetByProjectID_Call {
	return &ProjectAssetRepository_GetByProjectID_Call{Call: _e.mock.On("GetByProjectID", projectID)}
}

func (_c *ProjectAssetRepository_GetByProjectID_Call) Run(run func(projectID uuid.UUID)) *ProjectAssetRepository_GetByProjectID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectAssetRepository_GetByProjectID_Call) Return(_a0 []models.Asset, _a1 error) *ProjectAssetRepository_GetByProjectID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectAssetRepository_GetByProjectID_Call) RunAndReturn(run func(uuid.UUID) ([]models.Asset, error)) *ProjectAssetRepository_GetByProjectID_Call {
	_c.Call.Return(run)
	return _c
}

// NewProjectAssetRepository creates a new instance of ProjectAssetRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewProjectAssetRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ProjectAssetRepository {
	mock := &ProjectAssetRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
