// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	accesscontrol "github.com/l3montree-dev/devguard/internal/accesscontrol"
	mock "github.com/stretchr/testify/mock"
)

// AccesscontrolAccessControl is an autogenerated mock type for the AccessControl type
type AccesscontrolAccessControl struct {
	mock.Mock
}

type AccesscontrolAccessControl_Expecter struct {
	mock *mock.Mock
}

func (_m *AccesscontrolAccessControl) EXPECT() *AccesscontrolAccessControl_Expecter {
	return &AccesscontrolAccessControl_Expecter{mock: &_m.Mock}
}

// AllowRole provides a mock function with given fields: role, object, action
func (_m *AccesscontrolAccessControl) AllowRole(role string, object string, action []accesscontrol.Action) error {
	ret := _m.Called(role, object, action)

	if len(ret) == 0 {
		panic("no return value specified for AllowRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, []accesscontrol.Action) error); ok {
		r0 = rf(role, object, action)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_AllowRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AllowRole'
type AccesscontrolAccessControl_AllowRole_Call struct {
	*mock.Call
}

// AllowRole is a helper method to define mock.On call
//   - role string
//   - object string
//   - action []accesscontrol.Action
func (_e *AccesscontrolAccessControl_Expecter) AllowRole(role interface{}, object interface{}, action interface{}) *AccesscontrolAccessControl_AllowRole_Call {
	return &AccesscontrolAccessControl_AllowRole_Call{Call: _e.mock.On("AllowRole", role, object, action)}
}

func (_c *AccesscontrolAccessControl_AllowRole_Call) Run(run func(role string, object string, action []accesscontrol.Action)) *AccesscontrolAccessControl_AllowRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].([]accesscontrol.Action))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_AllowRole_Call) Return(_a0 error) *AccesscontrolAccessControl_AllowRole_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_AllowRole_Call) RunAndReturn(run func(string, string, []accesscontrol.Action) error) *AccesscontrolAccessControl_AllowRole_Call {
	_c.Call.Return(run)
	return _c
}

// AllowRoleInProject provides a mock function with given fields: project, role, object, action
func (_m *AccesscontrolAccessControl) AllowRoleInProject(project string, role string, object string, action []accesscontrol.Action) error {
	ret := _m.Called(project, role, object, action)

	if len(ret) == 0 {
		panic("no return value specified for AllowRoleInProject")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string, []accesscontrol.Action) error); ok {
		r0 = rf(project, role, object, action)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_AllowRoleInProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AllowRoleInProject'
type AccesscontrolAccessControl_AllowRoleInProject_Call struct {
	*mock.Call
}

// AllowRoleInProject is a helper method to define mock.On call
//   - project string
//   - role string
//   - object string
//   - action []accesscontrol.Action
func (_e *AccesscontrolAccessControl_Expecter) AllowRoleInProject(project interface{}, role interface{}, object interface{}, action interface{}) *AccesscontrolAccessControl_AllowRoleInProject_Call {
	return &AccesscontrolAccessControl_AllowRoleInProject_Call{Call: _e.mock.On("AllowRoleInProject", project, role, object, action)}
}

func (_c *AccesscontrolAccessControl_AllowRoleInProject_Call) Run(run func(project string, role string, object string, action []accesscontrol.Action)) *AccesscontrolAccessControl_AllowRoleInProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string), args[3].([]accesscontrol.Action))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_AllowRoleInProject_Call) Return(_a0 error) *AccesscontrolAccessControl_AllowRoleInProject_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_AllowRoleInProject_Call) RunAndReturn(run func(string, string, string, []accesscontrol.Action) error) *AccesscontrolAccessControl_AllowRoleInProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllMembersOfOrganization provides a mock function with no fields
func (_m *AccesscontrolAccessControl) GetAllMembersOfOrganization() ([]string, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetAllMembersOfOrganization")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]string, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_GetAllMembersOfOrganization_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllMembersOfOrganization'
type AccesscontrolAccessControl_GetAllMembersOfOrganization_Call struct {
	*mock.Call
}

// GetAllMembersOfOrganization is a helper method to define mock.On call
func (_e *AccesscontrolAccessControl_Expecter) GetAllMembersOfOrganization() *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call {
	return &AccesscontrolAccessControl_GetAllMembersOfOrganization_Call{Call: _e.mock.On("GetAllMembersOfOrganization")}
}

func (_c *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call) Run(run func()) *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call) Return(_a0 []string, _a1 error) *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call) RunAndReturn(run func() ([]string, error)) *AccesscontrolAccessControl_GetAllMembersOfOrganization_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllMembersOfProject provides a mock function with given fields: projectID
func (_m *AccesscontrolAccessControl) GetAllMembersOfProject(projectID string) ([]string, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetAllMembersOfProject")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]string, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_GetAllMembersOfProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllMembersOfProject'
type AccesscontrolAccessControl_GetAllMembersOfProject_Call struct {
	*mock.Call
}

// GetAllMembersOfProject is a helper method to define mock.On call
//   - projectID string
func (_e *AccesscontrolAccessControl_Expecter) GetAllMembersOfProject(projectID interface{}) *AccesscontrolAccessControl_GetAllMembersOfProject_Call {
	return &AccesscontrolAccessControl_GetAllMembersOfProject_Call{Call: _e.mock.On("GetAllMembersOfProject", projectID)}
}

func (_c *AccesscontrolAccessControl_GetAllMembersOfProject_Call) Run(run func(projectID string)) *AccesscontrolAccessControl_GetAllMembersOfProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllMembersOfProject_Call) Return(_a0 []string, _a1 error) *AccesscontrolAccessControl_GetAllMembersOfProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllMembersOfProject_Call) RunAndReturn(run func(string) ([]string, error)) *AccesscontrolAccessControl_GetAllMembersOfProject_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllProjectsForUser provides a mock function with given fields: user
func (_m *AccesscontrolAccessControl) GetAllProjectsForUser(user string) []string {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for GetAllProjectsForUser")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// AccesscontrolAccessControl_GetAllProjectsForUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllProjectsForUser'
type AccesscontrolAccessControl_GetAllProjectsForUser_Call struct {
	*mock.Call
}

// GetAllProjectsForUser is a helper method to define mock.On call
//   - user string
func (_e *AccesscontrolAccessControl_Expecter) GetAllProjectsForUser(user interface{}) *AccesscontrolAccessControl_GetAllProjectsForUser_Call {
	return &AccesscontrolAccessControl_GetAllProjectsForUser_Call{Call: _e.mock.On("GetAllProjectsForUser", user)}
}

func (_c *AccesscontrolAccessControl_GetAllProjectsForUser_Call) Run(run func(user string)) *AccesscontrolAccessControl_GetAllProjectsForUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllProjectsForUser_Call) Return(_a0 []string) *AccesscontrolAccessControl_GetAllProjectsForUser_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllProjectsForUser_Call) RunAndReturn(run func(string) []string) *AccesscontrolAccessControl_GetAllProjectsForUser_Call {
	_c.Call.Return(run)
	return _c
}

// GetAllRoles provides a mock function with given fields: user
func (_m *AccesscontrolAccessControl) GetAllRoles(user string) []string {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for GetAllRoles")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// AccesscontrolAccessControl_GetAllRoles_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAllRoles'
type AccesscontrolAccessControl_GetAllRoles_Call struct {
	*mock.Call
}

// GetAllRoles is a helper method to define mock.On call
//   - user string
func (_e *AccesscontrolAccessControl_Expecter) GetAllRoles(user interface{}) *AccesscontrolAccessControl_GetAllRoles_Call {
	return &AccesscontrolAccessControl_GetAllRoles_Call{Call: _e.mock.On("GetAllRoles", user)}
}

func (_c *AccesscontrolAccessControl_GetAllRoles_Call) Run(run func(user string)) *AccesscontrolAccessControl_GetAllRoles_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllRoles_Call) Return(_a0 []string) *AccesscontrolAccessControl_GetAllRoles_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_GetAllRoles_Call) RunAndReturn(run func(string) []string) *AccesscontrolAccessControl_GetAllRoles_Call {
	_c.Call.Return(run)
	return _c
}

// GetDomainRole provides a mock function with given fields: user
func (_m *AccesscontrolAccessControl) GetDomainRole(user string) (string, error) {
	ret := _m.Called(user)

	if len(ret) == 0 {
		panic("no return value specified for GetDomainRole")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_GetDomainRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDomainRole'
type AccesscontrolAccessControl_GetDomainRole_Call struct {
	*mock.Call
}

// GetDomainRole is a helper method to define mock.On call
//   - user string
func (_e *AccesscontrolAccessControl_Expecter) GetDomainRole(user interface{}) *AccesscontrolAccessControl_GetDomainRole_Call {
	return &AccesscontrolAccessControl_GetDomainRole_Call{Call: _e.mock.On("GetDomainRole", user)}
}

func (_c *AccesscontrolAccessControl_GetDomainRole_Call) Run(run func(user string)) *AccesscontrolAccessControl_GetDomainRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetDomainRole_Call) Return(_a0 string, _a1 error) *AccesscontrolAccessControl_GetDomainRole_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_GetDomainRole_Call) RunAndReturn(run func(string) (string, error)) *AccesscontrolAccessControl_GetDomainRole_Call {
	_c.Call.Return(run)
	return _c
}

// GetOwnerOfOrganization provides a mock function with no fields
func (_m *AccesscontrolAccessControl) GetOwnerOfOrganization() (string, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetOwnerOfOrganization")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func() (string, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_GetOwnerOfOrganization_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOwnerOfOrganization'
type AccesscontrolAccessControl_GetOwnerOfOrganization_Call struct {
	*mock.Call
}

// GetOwnerOfOrganization is a helper method to define mock.On call
func (_e *AccesscontrolAccessControl_Expecter) GetOwnerOfOrganization() *AccesscontrolAccessControl_GetOwnerOfOrganization_Call {
	return &AccesscontrolAccessControl_GetOwnerOfOrganization_Call{Call: _e.mock.On("GetOwnerOfOrganization")}
}

func (_c *AccesscontrolAccessControl_GetOwnerOfOrganization_Call) Run(run func()) *AccesscontrolAccessControl_GetOwnerOfOrganization_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetOwnerOfOrganization_Call) Return(_a0 string, _a1 error) *AccesscontrolAccessControl_GetOwnerOfOrganization_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_GetOwnerOfOrganization_Call) RunAndReturn(run func() (string, error)) *AccesscontrolAccessControl_GetOwnerOfOrganization_Call {
	_c.Call.Return(run)
	return _c
}

// GetProjectRole provides a mock function with given fields: user, project
func (_m *AccesscontrolAccessControl) GetProjectRole(user string, project string) (string, error) {
	ret := _m.Called(user, project)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectRole")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) (string, error)); ok {
		return rf(user, project)
	}
	if rf, ok := ret.Get(0).(func(string, string) string); ok {
		r0 = rf(user, project)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(user, project)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_GetProjectRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetProjectRole'
type AccesscontrolAccessControl_GetProjectRole_Call struct {
	*mock.Call
}

// GetProjectRole is a helper method to define mock.On call
//   - user string
//   - project string
func (_e *AccesscontrolAccessControl_Expecter) GetProjectRole(user interface{}, project interface{}) *AccesscontrolAccessControl_GetProjectRole_Call {
	return &AccesscontrolAccessControl_GetProjectRole_Call{Call: _e.mock.On("GetProjectRole", user, project)}
}

func (_c *AccesscontrolAccessControl_GetProjectRole_Call) Run(run func(user string, project string)) *AccesscontrolAccessControl_GetProjectRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GetProjectRole_Call) Return(_a0 string, _a1 error) *AccesscontrolAccessControl_GetProjectRole_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_GetProjectRole_Call) RunAndReturn(run func(string, string) (string, error)) *AccesscontrolAccessControl_GetProjectRole_Call {
	_c.Call.Return(run)
	return _c
}

// GrantRole provides a mock function with given fields: subject, role
func (_m *AccesscontrolAccessControl) GrantRole(subject string, role string) error {
	ret := _m.Called(subject, role)

	if len(ret) == 0 {
		panic("no return value specified for GrantRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(subject, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_GrantRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GrantRole'
type AccesscontrolAccessControl_GrantRole_Call struct {
	*mock.Call
}

// GrantRole is a helper method to define mock.On call
//   - subject string
//   - role string
func (_e *AccesscontrolAccessControl_Expecter) GrantRole(subject interface{}, role interface{}) *AccesscontrolAccessControl_GrantRole_Call {
	return &AccesscontrolAccessControl_GrantRole_Call{Call: _e.mock.On("GrantRole", subject, role)}
}

func (_c *AccesscontrolAccessControl_GrantRole_Call) Run(run func(subject string, role string)) *AccesscontrolAccessControl_GrantRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GrantRole_Call) Return(_a0 error) *AccesscontrolAccessControl_GrantRole_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_GrantRole_Call) RunAndReturn(run func(string, string) error) *AccesscontrolAccessControl_GrantRole_Call {
	_c.Call.Return(run)
	return _c
}

// GrantRoleInProject provides a mock function with given fields: subject, role, project
func (_m *AccesscontrolAccessControl) GrantRoleInProject(subject string, role string, project string) error {
	ret := _m.Called(subject, role, project)

	if len(ret) == 0 {
		panic("no return value specified for GrantRoleInProject")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(subject, role, project)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_GrantRoleInProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GrantRoleInProject'
type AccesscontrolAccessControl_GrantRoleInProject_Call struct {
	*mock.Call
}

// GrantRoleInProject is a helper method to define mock.On call
//   - subject string
//   - role string
//   - project string
func (_e *AccesscontrolAccessControl_Expecter) GrantRoleInProject(subject interface{}, role interface{}, project interface{}) *AccesscontrolAccessControl_GrantRoleInProject_Call {
	return &AccesscontrolAccessControl_GrantRoleInProject_Call{Call: _e.mock.On("GrantRoleInProject", subject, role, project)}
}

func (_c *AccesscontrolAccessControl_GrantRoleInProject_Call) Run(run func(subject string, role string, project string)) *AccesscontrolAccessControl_GrantRoleInProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_GrantRoleInProject_Call) Return(_a0 error) *AccesscontrolAccessControl_GrantRoleInProject_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_GrantRoleInProject_Call) RunAndReturn(run func(string, string, string) error) *AccesscontrolAccessControl_GrantRoleInProject_Call {
	_c.Call.Return(run)
	return _c
}

// HasAccess provides a mock function with given fields: subject
func (_m *AccesscontrolAccessControl) HasAccess(subject string) bool {
	ret := _m.Called(subject)

	if len(ret) == 0 {
		panic("no return value specified for HasAccess")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(subject)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// AccesscontrolAccessControl_HasAccess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HasAccess'
type AccesscontrolAccessControl_HasAccess_Call struct {
	*mock.Call
}

// HasAccess is a helper method to define mock.On call
//   - subject string
func (_e *AccesscontrolAccessControl_Expecter) HasAccess(subject interface{}) *AccesscontrolAccessControl_HasAccess_Call {
	return &AccesscontrolAccessControl_HasAccess_Call{Call: _e.mock.On("HasAccess", subject)}
}

func (_c *AccesscontrolAccessControl_HasAccess_Call) Run(run func(subject string)) *AccesscontrolAccessControl_HasAccess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_HasAccess_Call) Return(_a0 bool) *AccesscontrolAccessControl_HasAccess_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_HasAccess_Call) RunAndReturn(run func(string) bool) *AccesscontrolAccessControl_HasAccess_Call {
	_c.Call.Return(run)
	return _c
}

// InheritProjectRole provides a mock function with given fields: roleWhichGetsPermissions, roleWhichProvidesPermissions, project
func (_m *AccesscontrolAccessControl) InheritProjectRole(roleWhichGetsPermissions string, roleWhichProvidesPermissions string, project string) error {
	ret := _m.Called(roleWhichGetsPermissions, roleWhichProvidesPermissions, project)

	if len(ret) == 0 {
		panic("no return value specified for InheritProjectRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(roleWhichGetsPermissions, roleWhichProvidesPermissions, project)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_InheritProjectRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'InheritProjectRole'
type AccesscontrolAccessControl_InheritProjectRole_Call struct {
	*mock.Call
}

// InheritProjectRole is a helper method to define mock.On call
//   - roleWhichGetsPermissions string
//   - roleWhichProvidesPermissions string
//   - project string
func (_e *AccesscontrolAccessControl_Expecter) InheritProjectRole(roleWhichGetsPermissions interface{}, roleWhichProvidesPermissions interface{}, project interface{}) *AccesscontrolAccessControl_InheritProjectRole_Call {
	return &AccesscontrolAccessControl_InheritProjectRole_Call{Call: _e.mock.On("InheritProjectRole", roleWhichGetsPermissions, roleWhichProvidesPermissions, project)}
}

func (_c *AccesscontrolAccessControl_InheritProjectRole_Call) Run(run func(roleWhichGetsPermissions string, roleWhichProvidesPermissions string, project string)) *AccesscontrolAccessControl_InheritProjectRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_InheritProjectRole_Call) Return(_a0 error) *AccesscontrolAccessControl_InheritProjectRole_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_InheritProjectRole_Call) RunAndReturn(run func(string, string, string) error) *AccesscontrolAccessControl_InheritProjectRole_Call {
	_c.Call.Return(run)
	return _c
}

// InheritProjectRolesAcrossProjects provides a mock function with given fields: roleWhichGetsPermissions, roleWhichProvidesPermissions
func (_m *AccesscontrolAccessControl) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions accesscontrol.ProjectRole, roleWhichProvidesPermissions accesscontrol.ProjectRole) error {
	ret := _m.Called(roleWhichGetsPermissions, roleWhichProvidesPermissions)

	if len(ret) == 0 {
		panic("no return value specified for InheritProjectRolesAcrossProjects")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(accesscontrol.ProjectRole, accesscontrol.ProjectRole) error); ok {
		r0 = rf(roleWhichGetsPermissions, roleWhichProvidesPermissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'InheritProjectRolesAcrossProjects'
type AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call struct {
	*mock.Call
}

// InheritProjectRolesAcrossProjects is a helper method to define mock.On call
//   - roleWhichGetsPermissions accesscontrol.ProjectRole
//   - roleWhichProvidesPermissions accesscontrol.ProjectRole
func (_e *AccesscontrolAccessControl_Expecter) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions interface{}, roleWhichProvidesPermissions interface{}) *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call {
	return &AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call{Call: _e.mock.On("InheritProjectRolesAcrossProjects", roleWhichGetsPermissions, roleWhichProvidesPermissions)}
}

func (_c *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call) Run(run func(roleWhichGetsPermissions accesscontrol.ProjectRole, roleWhichProvidesPermissions accesscontrol.ProjectRole)) *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(accesscontrol.ProjectRole), args[1].(accesscontrol.ProjectRole))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call) Return(_a0 error) *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call) RunAndReturn(run func(accesscontrol.ProjectRole, accesscontrol.ProjectRole) error) *AccesscontrolAccessControl_InheritProjectRolesAcrossProjects_Call {
	_c.Call.Return(run)
	return _c
}

// InheritRole provides a mock function with given fields: roleWhichGetsPermissions, roleWhichProvidesPermissions
func (_m *AccesscontrolAccessControl) InheritRole(roleWhichGetsPermissions string, roleWhichProvidesPermissions string) error {
	ret := _m.Called(roleWhichGetsPermissions, roleWhichProvidesPermissions)

	if len(ret) == 0 {
		panic("no return value specified for InheritRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(roleWhichGetsPermissions, roleWhichProvidesPermissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_InheritRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'InheritRole'
type AccesscontrolAccessControl_InheritRole_Call struct {
	*mock.Call
}

// InheritRole is a helper method to define mock.On call
//   - roleWhichGetsPermissions string
//   - roleWhichProvidesPermissions string
func (_e *AccesscontrolAccessControl_Expecter) InheritRole(roleWhichGetsPermissions interface{}, roleWhichProvidesPermissions interface{}) *AccesscontrolAccessControl_InheritRole_Call {
	return &AccesscontrolAccessControl_InheritRole_Call{Call: _e.mock.On("InheritRole", roleWhichGetsPermissions, roleWhichProvidesPermissions)}
}

func (_c *AccesscontrolAccessControl_InheritRole_Call) Run(run func(roleWhichGetsPermissions string, roleWhichProvidesPermissions string)) *AccesscontrolAccessControl_InheritRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_InheritRole_Call) Return(_a0 error) *AccesscontrolAccessControl_InheritRole_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_InheritRole_Call) RunAndReturn(run func(string, string) error) *AccesscontrolAccessControl_InheritRole_Call {
	_c.Call.Return(run)
	return _c
}

// IsAllowed provides a mock function with given fields: subject, object, action
func (_m *AccesscontrolAccessControl) IsAllowed(subject string, object string, action accesscontrol.Action) (bool, error) {
	ret := _m.Called(subject, object, action)

	if len(ret) == 0 {
		panic("no return value specified for IsAllowed")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string, accesscontrol.Action) (bool, error)); ok {
		return rf(subject, object, action)
	}
	if rf, ok := ret.Get(0).(func(string, string, accesscontrol.Action) bool); ok {
		r0 = rf(subject, object, action)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(string, string, accesscontrol.Action) error); ok {
		r1 = rf(subject, object, action)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_IsAllowed_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsAllowed'
type AccesscontrolAccessControl_IsAllowed_Call struct {
	*mock.Call
}

// IsAllowed is a helper method to define mock.On call
//   - subject string
//   - object string
//   - action accesscontrol.Action
func (_e *AccesscontrolAccessControl_Expecter) IsAllowed(subject interface{}, object interface{}, action interface{}) *AccesscontrolAccessControl_IsAllowed_Call {
	return &AccesscontrolAccessControl_IsAllowed_Call{Call: _e.mock.On("IsAllowed", subject, object, action)}
}

func (_c *AccesscontrolAccessControl_IsAllowed_Call) Run(run func(subject string, object string, action accesscontrol.Action)) *AccesscontrolAccessControl_IsAllowed_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(accesscontrol.Action))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_IsAllowed_Call) Return(_a0 bool, _a1 error) *AccesscontrolAccessControl_IsAllowed_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_IsAllowed_Call) RunAndReturn(run func(string, string, accesscontrol.Action) (bool, error)) *AccesscontrolAccessControl_IsAllowed_Call {
	_c.Call.Return(run)
	return _c
}

// IsAllowedInProject provides a mock function with given fields: project, user, object, action
func (_m *AccesscontrolAccessControl) IsAllowedInProject(project string, user string, object string, action accesscontrol.Action) (bool, error) {
	ret := _m.Called(project, user, object, action)

	if len(ret) == 0 {
		panic("no return value specified for IsAllowedInProject")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string, string, accesscontrol.Action) (bool, error)); ok {
		return rf(project, user, object, action)
	}
	if rf, ok := ret.Get(0).(func(string, string, string, accesscontrol.Action) bool); ok {
		r0 = rf(project, user, object, action)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(string, string, string, accesscontrol.Action) error); ok {
		r1 = rf(project, user, object, action)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AccesscontrolAccessControl_IsAllowedInProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IsAllowedInProject'
type AccesscontrolAccessControl_IsAllowedInProject_Call struct {
	*mock.Call
}

// IsAllowedInProject is a helper method to define mock.On call
//   - project string
//   - user string
//   - object string
//   - action accesscontrol.Action
func (_e *AccesscontrolAccessControl_Expecter) IsAllowedInProject(project interface{}, user interface{}, object interface{}, action interface{}) *AccesscontrolAccessControl_IsAllowedInProject_Call {
	return &AccesscontrolAccessControl_IsAllowedInProject_Call{Call: _e.mock.On("IsAllowedInProject", project, user, object, action)}
}

func (_c *AccesscontrolAccessControl_IsAllowedInProject_Call) Run(run func(project string, user string, object string, action accesscontrol.Action)) *AccesscontrolAccessControl_IsAllowedInProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string), args[3].(accesscontrol.Action))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_IsAllowedInProject_Call) Return(_a0 bool, _a1 error) *AccesscontrolAccessControl_IsAllowedInProject_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AccesscontrolAccessControl_IsAllowedInProject_Call) RunAndReturn(run func(string, string, string, accesscontrol.Action) (bool, error)) *AccesscontrolAccessControl_IsAllowedInProject_Call {
	_c.Call.Return(run)
	return _c
}

// LinkDomainAndProjectRole provides a mock function with given fields: domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project
func (_m *AccesscontrolAccessControl) LinkDomainAndProjectRole(domainRoleWhichGetsPermission string, projectRoleWhichProvidesPermissions string, project string) error {
	ret := _m.Called(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project)

	if len(ret) == 0 {
		panic("no return value specified for LinkDomainAndProjectRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_LinkDomainAndProjectRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LinkDomainAndProjectRole'
type AccesscontrolAccessControl_LinkDomainAndProjectRole_Call struct {
	*mock.Call
}

// LinkDomainAndProjectRole is a helper method to define mock.On call
//   - domainRoleWhichGetsPermission string
//   - projectRoleWhichProvidesPermissions string
//   - project string
func (_e *AccesscontrolAccessControl_Expecter) LinkDomainAndProjectRole(domainRoleWhichGetsPermission interface{}, projectRoleWhichProvidesPermissions interface{}, project interface{}) *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call {
	return &AccesscontrolAccessControl_LinkDomainAndProjectRole_Call{Call: _e.mock.On("LinkDomainAndProjectRole", domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project)}
}

func (_c *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call) Run(run func(domainRoleWhichGetsPermission string, projectRoleWhichProvidesPermissions string, project string)) *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call) Return(_a0 error) *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call) RunAndReturn(run func(string, string, string) error) *AccesscontrolAccessControl_LinkDomainAndProjectRole_Call {
	_c.Call.Return(run)
	return _c
}

// RevokeRole provides a mock function with given fields: subject, role
func (_m *AccesscontrolAccessControl) RevokeRole(subject string, role string) error {
	ret := _m.Called(subject, role)

	if len(ret) == 0 {
		panic("no return value specified for RevokeRole")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(subject, role)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_RevokeRole_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RevokeRole'
type AccesscontrolAccessControl_RevokeRole_Call struct {
	*mock.Call
}

// RevokeRole is a helper method to define mock.On call
//   - subject string
//   - role string
func (_e *AccesscontrolAccessControl_Expecter) RevokeRole(subject interface{}, role interface{}) *AccesscontrolAccessControl_RevokeRole_Call {
	return &AccesscontrolAccessControl_RevokeRole_Call{Call: _e.mock.On("RevokeRole", subject, role)}
}

func (_c *AccesscontrolAccessControl_RevokeRole_Call) Run(run func(subject string, role string)) *AccesscontrolAccessControl_RevokeRole_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_RevokeRole_Call) Return(_a0 error) *AccesscontrolAccessControl_RevokeRole_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_RevokeRole_Call) RunAndReturn(run func(string, string) error) *AccesscontrolAccessControl_RevokeRole_Call {
	_c.Call.Return(run)
	return _c
}

// RevokeRoleInProject provides a mock function with given fields: subject, role, project
func (_m *AccesscontrolAccessControl) RevokeRoleInProject(subject string, role string, project string) error {
	ret := _m.Called(subject, role, project)

	if len(ret) == 0 {
		panic("no return value specified for RevokeRoleInProject")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(subject, role, project)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AccesscontrolAccessControl_RevokeRoleInProject_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RevokeRoleInProject'
type AccesscontrolAccessControl_RevokeRoleInProject_Call struct {
	*mock.Call
}

// RevokeRoleInProject is a helper method to define mock.On call
//   - subject string
//   - role string
//   - project string
func (_e *AccesscontrolAccessControl_Expecter) RevokeRoleInProject(subject interface{}, role interface{}, project interface{}) *AccesscontrolAccessControl_RevokeRoleInProject_Call {
	return &AccesscontrolAccessControl_RevokeRoleInProject_Call{Call: _e.mock.On("RevokeRoleInProject", subject, role, project)}
}

func (_c *AccesscontrolAccessControl_RevokeRoleInProject_Call) Run(run func(subject string, role string, project string)) *AccesscontrolAccessControl_RevokeRoleInProject_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *AccesscontrolAccessControl_RevokeRoleInProject_Call) Return(_a0 error) *AccesscontrolAccessControl_RevokeRoleInProject_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AccesscontrolAccessControl_RevokeRoleInProject_Call) RunAndReturn(run func(string, string, string) error) *AccesscontrolAccessControl_RevokeRoleInProject_Call {
	_c.Call.Return(run)
	return _c
}

// NewAccesscontrolAccessControl creates a new instance of AccesscontrolAccessControl. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAccesscontrolAccessControl(t interface {
	mock.TestingT
	Cleanup(func())
}) *AccesscontrolAccessControl {
	mock := &AccesscontrolAccessControl{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
