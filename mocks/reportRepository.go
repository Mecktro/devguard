// Code generated by mockery v2.36.0. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/flawfix/internal/models"
	sarif "github.com/owenrumney/go-sarif/sarif"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// reportRepository is an autogenerated mock type for the reportRepository type
type reportRepository struct {
	mock.Mock
}

// Delete provides a mock function with given fields: _a0
func (_m *reportRepository) Delete(_a0 uuid.UUID) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Read provides a mock function with given fields: _a0
func (_m *reportRepository) Read(_a0 uuid.UUID) (models.Report, error) {
	ret := _m.Called(_a0)

	var r0 models.Report
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.Report, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.Report); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(models.Report)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SaveSarifReport provides a mock function with given fields: applicationID, report
func (_m *reportRepository) SaveSarifReport(applicationID string, report *sarif.Report) ([]models.Report, error) {
	ret := _m.Called(applicationID, report)

	var r0 []models.Report
	var r1 error
	if rf, ok := ret.Get(0).(func(string, *sarif.Report) ([]models.Report, error)); ok {
		return rf(applicationID, report)
	}
	if rf, ok := ret.Get(0).(func(string, *sarif.Report) []models.Report); ok {
		r0 = rf(applicationID, report)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Report)
		}
	}

	if rf, ok := ret.Get(1).(func(string, *sarif.Report) error); ok {
		r1 = rf(applicationID, report)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: _a0
func (_m *reportRepository) Update(_a0 *models.Report) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(*models.Report) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// newReportRepository creates a new instance of reportRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newReportRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *reportRepository {
	mock := &reportRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
