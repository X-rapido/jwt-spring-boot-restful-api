package com.tingfeng.model;

public enum Role {
    ADMIN,   // 管理员
    MEMBER;  // 会员

    public String authority() {
        return "ROLE_" + this.name();
    }

    @Override
    public String toString() {
        return this.name();
    }
}
