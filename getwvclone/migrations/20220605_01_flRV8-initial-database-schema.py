"""
initial-database-schema
"""

from yoyo import step

__depends__ = {}

steps = [
    step(
        """
        create table users
        (
            id            varchar(18)   not null
                primary key,
            username      text          not null,
            discriminator text          not null,
            avatar        text          null,
            public_flags  int           not null,
            api_key       text          not null,
            disabled      int default 0 not null,
            is_admin      int default 0 not null,
            constraint users_id_uindex
                unique (id)
        );
        """
    ),
    step(
        """
        create table keys_
        (
            id          int auto_increment
                primary key,
            kid         varchar(32)                           not null,
            added_at    int default unix_timestamp()          not null,
            added_by    varchar(18)                           null,
            license_url text                                  null,
            key_        varchar(65)                           null,
            constraint keys_id_uindex
                unique (id),
            constraint keys_key__uindex
                unique (key_),
            constraint keys_users_id_fk
                foreign key (added_by) references users (id)
                    on update cascade on delete cascade
        );
        """
    ),
    step(
        """
        create table `cdms`
        (
            id                      int auto_increment
                primary key,
            session_id_type         text default 'android' not null,
            security_level          int  default 3         not null,
            client_id_blob_filename text                   null,
            device_private_key      text                   not null,
            code                    varchar(255)           not null,
            uploaded_by             varchar(18)            not null,
            constraint cdms_code_uindex
                unique (code),
            constraint cdms_id_uindex
                unique (id),
            constraint cdms_users_id_fk
                foreign key (uploaded_by) references users (id)
                    on update cascade on delete cascade
        );
        """
    ),
]
