package com.tingfeng.service;

import com.tingfeng.model.Person;

public interface PersonService {

    /**
     * 保存用户到 Ignite DB
     *
     * @param person Person Object
     * @return The Person object saved in Ignite DB.
     */
    Person save(Person person);

    /**
     * 在 Ignite DB 中查找用户
     *
     * @param name Person name.
     * @return The person found in Ignite DB
     */
    Person findPersonByUsername(String name);
}
