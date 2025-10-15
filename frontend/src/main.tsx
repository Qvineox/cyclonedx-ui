import {createRoot} from 'react-dom/client'
import {RouterProvider} from "react-router-dom";
import router from "./router.tsx";
import "../src/styles/index.scss"

import 'bootstrap/dist/css/bootstrap.min.css';

import DataTable from 'datatables.net-react';
import DT from 'datatables.net-bs5';

// DT.ext.type.order['my-custom-type-asc'] = function (a, b) {
//     return ((a < b) ? -1 : ((a > b) ? 1 : 0));
// };
//
// DT.ext.type.order['my-custom-type-desc'] = function (a, b) {
//     // Custom descending comparison logic
//     return ((a < b) ? 1 : ((a > b) ? -1 : 0));
// };

DataTable.use(DT);


createRoot(document.getElementById('root')!).render(
    <RouterProvider router={router}/>
)
