// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	context "context"

	core "github.com/l3montree-dev/devguard/internal/core"
	echo "github.com/labstack/echo/v4"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// IntegrationAggregate is an autogenerated mock type for the IntegrationAggregate type
type IntegrationAggregate struct {
	mock.Mock
}

type IntegrationAggregate_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationAggregate) EXPECT() *IntegrationAggregate_Expecter {
	return &IntegrationAggregate_Expecter{mock: &_m.Mock}
}

// CloseIssue provides a mock function with given fields: ctx, state, repoId, dependencyVuln
func (_m *IntegrationAggregate) CloseIssue(ctx context.Context, state string, repoId string, dependencyVuln models.DependencyVuln) error {
	ret := _m.Called(ctx, state, repoId, dependencyVuln)

	if len(ret) == 0 {
		panic("no return value specified for CloseIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, models.DependencyVuln) error); ok {
		r0 = rf(ctx, state, repoId, dependencyVuln)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationAggregate_CloseIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CloseIssue'
type IntegrationAggregate_CloseIssue_Call struct {
	*mock.Call
}

// CloseIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - state string
//   - repoId string
//   - dependencyVuln models.DependencyVuln
func (_e *IntegrationAggregate_Expecter) CloseIssue(ctx interface{}, state interface{}, repoId interface{}, dependencyVuln interface{}) *IntegrationAggregate_CloseIssue_Call {
	return &IntegrationAggregate_CloseIssue_Call{Call: _e.mock.On("CloseIssue", ctx, state, repoId, dependencyVuln)}
}

func (_c *IntegrationAggregate_CloseIssue_Call) Run(run func(ctx context.Context, state string, repoId string, dependencyVuln models.DependencyVuln)) *IntegrationAggregate_CloseIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(models.DependencyVuln))
	})
	return _c
}

func (_c *IntegrationAggregate_CloseIssue_Call) Return(_a0 error) *IntegrationAggregate_CloseIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_CloseIssue_Call) RunAndReturn(run func(context.Context, string, string, models.DependencyVuln) error) *IntegrationAggregate_CloseIssue_Call {
	_c.Call.Return(run)
	return _c
}

// CreateIssue provides a mock function with given fields: ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug, justification, manualTicketCreation
func (_m *IntegrationAggregate) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, dependencyVuln models.DependencyVuln, projectSlug string, orgSlug string, justification string, manualTicketCreation bool) error {
	ret := _m.Called(ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug, justification, manualTicketCreation)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, models.Asset, string, string, models.DependencyVuln, string, string, string, bool) error); ok {
		r0 = rf(ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug, justification, manualTicketCreation)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationAggregate_CreateIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssue'
type IntegrationAggregate_CreateIssue_Call struct {
	*mock.Call
}

// CreateIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - asset models.Asset
//   - assetVersionName string
//   - repoId string
//   - dependencyVuln models.DependencyVuln
//   - projectSlug string
//   - orgSlug string
//   - justification string
//   - manualTicketCreation bool
func (_e *IntegrationAggregate_Expecter) CreateIssue(ctx interface{}, asset interface{}, assetVersionName interface{}, repoId interface{}, dependencyVuln interface{}, projectSlug interface{}, orgSlug interface{}, justification interface{}, manualTicketCreation interface{}) *IntegrationAggregate_CreateIssue_Call {
	return &IntegrationAggregate_CreateIssue_Call{Call: _e.mock.On("CreateIssue", ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug, justification, manualTicketCreation)}
}

func (_c *IntegrationAggregate_CreateIssue_Call) Run(run func(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, dependencyVuln models.DependencyVuln, projectSlug string, orgSlug string, justification string, manualTicketCreation bool)) *IntegrationAggregate_CreateIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(models.Asset), args[2].(string), args[3].(string), args[4].(models.DependencyVuln), args[5].(string), args[6].(string), args[7].(string), args[8].(bool))
	})
	return _c
}

func (_c *IntegrationAggregate_CreateIssue_Call) Return(_a0 error) *IntegrationAggregate_CreateIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_CreateIssue_Call) RunAndReturn(run func(context.Context, models.Asset, string, string, models.DependencyVuln, string, string, string, bool) error) *IntegrationAggregate_CreateIssue_Call {
	_c.Call.Return(run)
	return _c
}

// GetID provides a mock function with no fields
func (_m *IntegrationAggregate) GetID() core.IntegrationID {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetID")
	}

	var r0 core.IntegrationID
	if rf, ok := ret.Get(0).(func() core.IntegrationID); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(core.IntegrationID)
	}

	return r0
}

// IntegrationAggregate_GetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetID'
type IntegrationAggregate_GetID_Call struct {
	*mock.Call
}

// GetID is a helper method to define mock.On call
func (_e *IntegrationAggregate_Expecter) GetID() *IntegrationAggregate_GetID_Call {
	return &IntegrationAggregate_GetID_Call{Call: _e.mock.On("GetID")}
}

func (_c *IntegrationAggregate_GetID_Call) Run(run func()) *IntegrationAggregate_GetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *IntegrationAggregate_GetID_Call) Return(_a0 core.IntegrationID) *IntegrationAggregate_GetID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_GetID_Call) RunAndReturn(run func() core.IntegrationID) *IntegrationAggregate_GetID_Call {
	_c.Call.Return(run)
	return _c
}

// GetIntegration provides a mock function with given fields: id
func (_m *IntegrationAggregate) GetIntegration(id core.IntegrationID) core.ThirdPartyIntegration {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for GetIntegration")
	}

	var r0 core.ThirdPartyIntegration
	if rf, ok := ret.Get(0).(func(core.IntegrationID) core.ThirdPartyIntegration); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(core.ThirdPartyIntegration)
		}
	}

	return r0
}

// IntegrationAggregate_GetIntegration_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetIntegration'
type IntegrationAggregate_GetIntegration_Call struct {
	*mock.Call
}

// GetIntegration is a helper method to define mock.On call
//   - id core.IntegrationID
func (_e *IntegrationAggregate_Expecter) GetIntegration(id interface{}) *IntegrationAggregate_GetIntegration_Call {
	return &IntegrationAggregate_GetIntegration_Call{Call: _e.mock.On("GetIntegration", id)}
}

func (_c *IntegrationAggregate_GetIntegration_Call) Run(run func(id core.IntegrationID)) *IntegrationAggregate_GetIntegration_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(core.IntegrationID))
	})
	return _c
}

func (_c *IntegrationAggregate_GetIntegration_Call) Return(_a0 core.ThirdPartyIntegration) *IntegrationAggregate_GetIntegration_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_GetIntegration_Call) RunAndReturn(run func(core.IntegrationID) core.ThirdPartyIntegration) *IntegrationAggregate_GetIntegration_Call {
	_c.Call.Return(run)
	return _c
}

// GetUsers provides a mock function with given fields: org
func (_m *IntegrationAggregate) GetUsers(org models.Org) []core.User {
	ret := _m.Called(org)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 []core.User
	if rf, ok := ret.Get(0).(func(models.Org) []core.User); ok {
		r0 = rf(org)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.User)
		}
	}

	return r0
}

// IntegrationAggregate_GetUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUsers'
type IntegrationAggregate_GetUsers_Call struct {
	*mock.Call
}

// GetUsers is a helper method to define mock.On call
//   - org models.Org
func (_e *IntegrationAggregate_Expecter) GetUsers(org interface{}) *IntegrationAggregate_GetUsers_Call {
	return &IntegrationAggregate_GetUsers_Call{Call: _e.mock.On("GetUsers", org)}
}

func (_c *IntegrationAggregate_GetUsers_Call) Run(run func(org models.Org)) *IntegrationAggregate_GetUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Org))
	})
	return _c
}

func (_c *IntegrationAggregate_GetUsers_Call) Return(_a0 []core.User) *IntegrationAggregate_GetUsers_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_GetUsers_Call) RunAndReturn(run func(models.Org) []core.User) *IntegrationAggregate_GetUsers_Call {
	_c.Call.Return(run)
	return _c
}

// HandleEvent provides a mock function with given fields: event
func (_m *IntegrationAggregate) HandleEvent(event interface{}) error {
	ret := _m.Called(event)

	if len(ret) == 0 {
		panic("no return value specified for HandleEvent")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationAggregate_HandleEvent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleEvent'
type IntegrationAggregate_HandleEvent_Call struct {
	*mock.Call
}

// HandleEvent is a helper method to define mock.On call
//   - event interface{}
func (_e *IntegrationAggregate_Expecter) HandleEvent(event interface{}) *IntegrationAggregate_HandleEvent_Call {
	return &IntegrationAggregate_HandleEvent_Call{Call: _e.mock.On("HandleEvent", event)}
}

func (_c *IntegrationAggregate_HandleEvent_Call) Run(run func(event interface{})) *IntegrationAggregate_HandleEvent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *IntegrationAggregate_HandleEvent_Call) Return(_a0 error) *IntegrationAggregate_HandleEvent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_HandleEvent_Call) RunAndReturn(run func(interface{}) error) *IntegrationAggregate_HandleEvent_Call {
	_c.Call.Return(run)
	return _c
}

// HandleWebhook provides a mock function with given fields: ctx
func (_m *IntegrationAggregate) HandleWebhook(ctx echo.Context) error {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for HandleWebhook")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(echo.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationAggregate_HandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleWebhook'
type IntegrationAggregate_HandleWebhook_Call struct {
	*mock.Call
}

// HandleWebhook is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *IntegrationAggregate_Expecter) HandleWebhook(ctx interface{}) *IntegrationAggregate_HandleWebhook_Call {
	return &IntegrationAggregate_HandleWebhook_Call{Call: _e.mock.On("HandleWebhook", ctx)}
}

func (_c *IntegrationAggregate_HandleWebhook_Call) Run(run func(ctx echo.Context)) *IntegrationAggregate_HandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *IntegrationAggregate_HandleWebhook_Call) Return(_a0 error) *IntegrationAggregate_HandleWebhook_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_HandleWebhook_Call) RunAndReturn(run func(echo.Context) error) *IntegrationAggregate_HandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// IntegrationEnabled provides a mock function with given fields: ctx
func (_m *IntegrationAggregate) IntegrationEnabled(ctx echo.Context) bool {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for IntegrationEnabled")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(echo.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IntegrationAggregate_IntegrationEnabled_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IntegrationEnabled'
type IntegrationAggregate_IntegrationEnabled_Call struct {
	*mock.Call
}

// IntegrationEnabled is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *IntegrationAggregate_Expecter) IntegrationEnabled(ctx interface{}) *IntegrationAggregate_IntegrationEnabled_Call {
	return &IntegrationAggregate_IntegrationEnabled_Call{Call: _e.mock.On("IntegrationEnabled", ctx)}
}

func (_c *IntegrationAggregate_IntegrationEnabled_Call) Run(run func(ctx echo.Context)) *IntegrationAggregate_IntegrationEnabled_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *IntegrationAggregate_IntegrationEnabled_Call) Return(_a0 bool) *IntegrationAggregate_IntegrationEnabled_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_IntegrationEnabled_Call) RunAndReturn(run func(echo.Context) bool) *IntegrationAggregate_IntegrationEnabled_Call {
	_c.Call.Return(run)
	return _c
}

// ListRepositories provides a mock function with given fields: ctx
func (_m *IntegrationAggregate) ListRepositories(ctx echo.Context) ([]core.Repository, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListRepositories")
	}

	var r0 []core.Repository
	var r1 error
	if rf, ok := ret.Get(0).(func(echo.Context) ([]core.Repository, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(echo.Context) []core.Repository); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(echo.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationAggregate_ListRepositories_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListRepositories'
type IntegrationAggregate_ListRepositories_Call struct {
	*mock.Call
}

// ListRepositories is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *IntegrationAggregate_Expecter) ListRepositories(ctx interface{}) *IntegrationAggregate_ListRepositories_Call {
	return &IntegrationAggregate_ListRepositories_Call{Call: _e.mock.On("ListRepositories", ctx)}
}

func (_c *IntegrationAggregate_ListRepositories_Call) Run(run func(ctx echo.Context)) *IntegrationAggregate_ListRepositories_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *IntegrationAggregate_ListRepositories_Call) Return(_a0 []core.Repository, _a1 error) *IntegrationAggregate_ListRepositories_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationAggregate_ListRepositories_Call) RunAndReturn(run func(echo.Context) ([]core.Repository, error)) *IntegrationAggregate_ListRepositories_Call {
	_c.Call.Return(run)
	return _c
}

// ReopenIssue provides a mock function with given fields: ctx, repoId, dependencyVuln
func (_m *IntegrationAggregate) ReopenIssue(ctx context.Context, repoId string, dependencyVuln models.DependencyVuln) error {
	ret := _m.Called(ctx, repoId, dependencyVuln)

	if len(ret) == 0 {
		panic("no return value specified for ReopenIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, models.DependencyVuln) error); ok {
		r0 = rf(ctx, repoId, dependencyVuln)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationAggregate_ReopenIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReopenIssue'
type IntegrationAggregate_ReopenIssue_Call struct {
	*mock.Call
}

// ReopenIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - repoId string
//   - dependencyVuln models.DependencyVuln
func (_e *IntegrationAggregate_Expecter) ReopenIssue(ctx interface{}, repoId interface{}, dependencyVuln interface{}) *IntegrationAggregate_ReopenIssue_Call {
	return &IntegrationAggregate_ReopenIssue_Call{Call: _e.mock.On("ReopenIssue", ctx, repoId, dependencyVuln)}
}

func (_c *IntegrationAggregate_ReopenIssue_Call) Run(run func(ctx context.Context, repoId string, dependencyVuln models.DependencyVuln)) *IntegrationAggregate_ReopenIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(models.DependencyVuln))
	})
	return _c
}

func (_c *IntegrationAggregate_ReopenIssue_Call) Return(_a0 error) *IntegrationAggregate_ReopenIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_ReopenIssue_Call) RunAndReturn(run func(context.Context, string, models.DependencyVuln) error) *IntegrationAggregate_ReopenIssue_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateIssue provides a mock function with given fields: ctx, asset, repoId, dependencyVuln
func (_m *IntegrationAggregate) UpdateIssue(ctx context.Context, asset models.Asset, repoId string, dependencyVuln models.DependencyVuln) error {
	ret := _m.Called(ctx, asset, repoId, dependencyVuln)

	if len(ret) == 0 {
		panic("no return value specified for UpdateIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, models.Asset, string, models.DependencyVuln) error); ok {
		r0 = rf(ctx, asset, repoId, dependencyVuln)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationAggregate_UpdateIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateIssue'
type IntegrationAggregate_UpdateIssue_Call struct {
	*mock.Call
}

// UpdateIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - asset models.Asset
//   - repoId string
//   - dependencyVuln models.DependencyVuln
func (_e *IntegrationAggregate_Expecter) UpdateIssue(ctx interface{}, asset interface{}, repoId interface{}, dependencyVuln interface{}) *IntegrationAggregate_UpdateIssue_Call {
	return &IntegrationAggregate_UpdateIssue_Call{Call: _e.mock.On("UpdateIssue", ctx, asset, repoId, dependencyVuln)}
}

func (_c *IntegrationAggregate_UpdateIssue_Call) Run(run func(ctx context.Context, asset models.Asset, repoId string, dependencyVuln models.DependencyVuln)) *IntegrationAggregate_UpdateIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(models.Asset), args[2].(string), args[3].(models.DependencyVuln))
	})
	return _c
}

func (_c *IntegrationAggregate_UpdateIssue_Call) Return(_a0 error) *IntegrationAggregate_UpdateIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_UpdateIssue_Call) RunAndReturn(run func(context.Context, models.Asset, string, models.DependencyVuln) error) *IntegrationAggregate_UpdateIssue_Call {
	_c.Call.Return(run)
	return _c
}

// WantsToHandleWebhook provides a mock function with given fields: ctx
func (_m *IntegrationAggregate) WantsToHandleWebhook(ctx echo.Context) bool {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for WantsToHandleWebhook")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(echo.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IntegrationAggregate_WantsToHandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WantsToHandleWebhook'
type IntegrationAggregate_WantsToHandleWebhook_Call struct {
	*mock.Call
}

// WantsToHandleWebhook is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *IntegrationAggregate_Expecter) WantsToHandleWebhook(ctx interface{}) *IntegrationAggregate_WantsToHandleWebhook_Call {
	return &IntegrationAggregate_WantsToHandleWebhook_Call{Call: _e.mock.On("WantsToHandleWebhook", ctx)}
}

func (_c *IntegrationAggregate_WantsToHandleWebhook_Call) Run(run func(ctx echo.Context)) *IntegrationAggregate_WantsToHandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *IntegrationAggregate_WantsToHandleWebhook_Call) Return(_a0 bool) *IntegrationAggregate_WantsToHandleWebhook_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationAggregate_WantsToHandleWebhook_Call) RunAndReturn(run func(echo.Context) bool) *IntegrationAggregate_WantsToHandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationAggregate creates a new instance of IntegrationAggregate. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationAggregate(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationAggregate {
	mock := &IntegrationAggregate{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
