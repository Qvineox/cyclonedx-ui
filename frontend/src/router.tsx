import {createBrowserRouter, Navigate} from "react-router-dom";
import RootLayout from "./layout/root.tsx";
import {InspectPage} from "./pages/inspect.tsx";
import {ComparePage} from "./pages/compare.tsx";

const router = createBrowserRouter([
    {
        path: "/",
        element: <RootLayout/>,
        children: [
            {
                path: "/",
                element: <Navigate to="/inspect" replace/>,
            },
            {
                path: "/inspect",
                element: <InspectPage/>
            },
            {
                path: "/compare",
                element: <ComparePage/>
            }
        ]
    },
    {
        path: "*", element: <Navigate to="/inspect" replace/>,
    }
])

export default router;