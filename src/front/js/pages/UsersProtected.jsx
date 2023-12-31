import React, { useContext, useEffect, useState } from "react"
import { Context } from "../store/appContext"
import { Navigate } from "react-router-dom"


const UsersProtected = () => {
    const { store, actions } = useContext(Context)




    useEffect(() => {
        actions.getUser()
    }, [])


    return (
        <>
            {
                store.token == null ?
                    <Navigate to={"/login"} /> :
                    <>
                        <h1>Hola welcome</h1>
                        {store.users.map((item) => {
                            return (
                                <p>{item.email}</p>
                            )
                        })}
                    </>
            }
        </>
    )
}


export default UsersProtected