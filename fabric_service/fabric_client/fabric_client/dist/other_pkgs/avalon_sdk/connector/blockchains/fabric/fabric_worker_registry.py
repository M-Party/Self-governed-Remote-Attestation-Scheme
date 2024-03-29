# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binascii
import logging
from os import environ

from dist.other_pkgs.avalon_sdk.connector.blockchains.common.contract_response \
    import ContractResponse
from dist.other_pkgs.avalon_sdk.worker.worker_details import WorkerStatus, WorkerType
from dist.other_pkgs.avalon_sdk.connector.blockchains.fabric.fabric_wrapper \
    import FabricWrapper
from dist.other_pkgs.avalon_sdk.connector.interfaces.worker_registry \
    import WorkerRegistry
from dist.other_pkgs.avalon_sdk.worker.worker_details import WorkerDetails

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)


class FabricWorkerRegistryImpl(WorkerRegistry):
    """
    This class provide worker APIs which interact with the
    Hyperledger Fabric blockchain.
    Detailed method descriptions are available in the WorkerRegistry
    interface.
    """

    def __init__(self, config):
        """
        Parameters:
        config    Dictionary containing Fabric-specific parameters
        """
        self.__fabric_wrapper = None
        # Chain code name
        self.CHAIN_CODE = 'worker'
        if config is not None:
            self.__fabric_wrapper = FabricWrapper(config)
        else:
            raise Exception("config is none")

    def worker_lookup(self, worker_type=None, org_id=None,
                      application_id=None, id=None):
        """
        Lookup a worker identified worker_type, org_id, and application_id.
        All fields are optional and, if present, condition should match for
        all fields. If none are passed it should return all workers.

        If the list is too large to fit into a single response (the maximum
        number of entries in a single response is implementation specific),
        the smart contract should return the first batch of the results
        and provide a lookup_tag that can be used by the caller to
        retrieve the next batch by calling worker_lookup_next.

        Parameters:
        worker_type         Optional characteristic of workers for which
                            you may wish to search
        org_id              Optional organization ID to which a worker belongs
        application_id      Optional application type ID that is
                            supported by the worker
        id                  Optional JSON RPC request ID

        Returns:
        Tuple containing workers count, lookup tag, and list of
        worker IDs:
        total_count Total number of entries matching a specified
                    lookup criteria. If this number is larger than the
                    size of the IDs array, the caller should use
                    lookupTag to call worker_lookup_next to retrieve
                    the rest of the IDs
        lookup_tag  Optional parameter. If it is returned, it means
                    that there are more matching worker IDs, which can then
                    be retrieved by calling function worker_lookup_next
                    with this tag as an input parameter
        ids         Array of the worker IDs that match the input parameters

        On error returns None.
        """
        if (self.__fabric_wrapper is not None):
            params = []
            if worker_type is None:
                params.append(str(0))
            else:
                params.append(str(worker_type.value))

            if org_id is None:
                params.append("")
            else:
                params.append(org_id)

            if application_id is None:
                params.append("")
            else:
                params.append(application_id)

            logging.info("Worker lookup args {}".format(params))
            lookupResult = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'workerLookUp',
                params)
            return lookupResult
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def worker_retrieve(self, worker_id, id=None):
        """
        Retrieve the worker identified by worker ID.

        Parameters:
        worker_id  Worker ID of the registry whose details are requested
        id         Optional Optional JSON RPC request ID

        Returns:
        Tuple containing worker status (defined in worker_set_status),
        worker type, organization ID, list of application IDs, and worker
        details (JSON RPC string).

        On error returns None.
        """
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            workerDetails = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'workerRetrieve',
                params)
            return workerDetails
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def worker_lookup_next(self, worker_type, org_id, application_id,
                           lookup_tag, id=None):
        """
        Retrieve additional worker lookup results after calling worker_lookup.

        Parameters:
        worker_type         Characteristic of Workers for which you may wish
                            to search.
        org_id              Organization ID to which a worker belongs
        application_id      Optional application type ID that is
                            supported by the worker
        lookup_tag          is returned by a previous call to either this
                            function or to worker_lookup
        id                  Optional Optional JSON RPC request ID

        Returns:
        Tuple containing the following:
        total_count    Total number of entries matching this lookup
                       criteria.  If this number is larger than the number
                       of IDs returned so far, the caller should use
                       lookupTag to call worker_lookup_next to retrieve
                       the rest of the IDs
        new_lookup_tag Optional parameter. If it is returned, it
                       means that there are more matching worker IDs that
                       can be retrieved by calling this function again with
                       this tag as an input parameter
        ids            Array of the worker IDs that match the input parameters

        On error returns None.
        """
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(str(worker_type.value))
            params.append(org_id)
            params.append(application_id)
            params.append(lookup_tag)
            lookupResult = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'workerLookUpNext',
                params)
            return lookupResult
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def worker_register(self, worker_id, worker_type, org_id,
                        application_ids, details, id=None):
        """
        Register a new worker with details of the worker.

        Parameters:
        worker_id       Worker ID value. E.g., a Fabric address
        worker_type     Type of Worker. Currently defined types are:
                        * "TEE-SGX": an Intel SGX Trusted Execution
                          Environment
                        * "MPC": Multi-Party Compute
                        * "ZK": Zero-Knowledge
        org_id          Optional parameter representing the
                        organization that hosts the Worker,
                        e.g. a bank in the consortium or
                        anonymous entity
        application_ids Optional parameter that defines
                        application types supported by the Worker
        details         Detailed information about the worker in
                        JSON RPC format as defined in
                https://entethalliance.github.io/trusted-computing/spec.html
                #common-data-for-all-worker-types
        id              Optional Optional JSON RPC request ID

        Returns:
        ContractResponse.SUCCESS on success or
        ContractResponse.ERROR on error.
        """
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(str(worker_type.value))
            params.append(org_id)
            params.append(','.join(application_ids))
            params.append(details)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'workerRegister',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def worker_set_status(self, worker_id, status, id=None):
        """
        Set the registry status identified by worker ID

        Parameters:
        worker_id Worker ID value. E.g., a Fabric address
        status    Worker status. The currently defined values are:
                  1 - worker is active
                  2 - worker is temporarily "off-line"
                  3 - worker is decommissioned
                  4 - worker is compromised
        id        Optional Optional JSON RPC request ID

        Returns:
        ContractResponse.SUCCESS on success
        or ContractResponse.ERROR on error.
        """
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(str(status.value))
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'workerSetStatus',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def worker_update(self, worker_id, details, id=None):
        """
        Update a worker with details data.

        Parameters:
        worker_id  Worker ID, e.g. a Fabric address
        details    Detailed information about the worker in JSON format
        id         Optional Optional JSON RPC request ID

        Returns:
        ContractResponse.SUCCESS on success
        or ContractResponse.ERROR on error.
        """
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(details)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'workerUpdate',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def generate_nonce(self, worker_id, nonce):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(nonce)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'generateNonce',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def get_nonce(self, worker_ids):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_ids)
            nonce = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'getNonce',
                params)
            return nonce
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def remove_nonce(self, worker_id):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'removeNonce',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def upload_quote(self, worker_id, quote):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(quote)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'uploadQuote',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def get_quote(self, worker_id):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            quote = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'getQuote',
                params)
            return quote
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None
        
    def get_quote_by_ids(self, worker_ids):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_ids)
            quote = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'getQuoteByIds',
                params)
            return quote
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def upload_verify_result(self, worker_id, verify_results):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(verify_results)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'uploadVerifyResult',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def get_verify_final_result(self, worker_ids):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_ids)
            verifyFinalResult = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'getVerifyFinalResult',
                params)
            return verifyFinalResult
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def upload_customer_enclaves(self, customer_enclaves):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(customer_enclaves)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'uploadCustomerEnclaves',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def get_customer_enclaves(self, job_ids):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(job_ids)
            customerEnclaves = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'getCustomerEnclaves',
                params)
            return customerEnclaves
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return None

    def send_heartbeat(self, worker_id):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            txn_status = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'sendHeartbeat',
                params)
            return txn_status
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR

    def check_heartbeat(self, worker_id, worker_ids):
        if (self.__fabric_wrapper is not None):
            params = []
            params.append(worker_id)
            params.append(worker_ids)
            check_results = self.__fabric_wrapper.invoke_chaincode(
                self.CHAIN_CODE,
                'checkHeartbeat',
                params)
            return check_results
        else:
            logging.error("Fabric wrapper instance is not initialized")
            return ContractResponse.ERROR