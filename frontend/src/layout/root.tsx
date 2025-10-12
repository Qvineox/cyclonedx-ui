import {Outlet} from "react-router-dom";
import {Fragment} from "react";
import Navbar from "./navbar/navbar.tsx";

export default function RootLayout() {
    return <Fragment>
        <Navbar/>
        <div id="root-layout">
            <Outlet/>
        </div>
    </Fragment>
}