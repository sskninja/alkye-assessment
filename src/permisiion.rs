use crate::model::UserType;

pub struct UserPermission {
    pub create_task: bool,
    pub assign_task: bool,
}

pub fn check_permission(user_type: &UserType) -> UserPermission {
    match user_type {
        UserType::Admin => UserPermission {
            create_task: true,
            assign_task: true,
        },
        UserType::User => UserPermission {
            create_task: false,
            assign_task: false,
        },
    }
}
