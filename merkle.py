import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# class that represents a node in tree-holds fields of left,right,parent,value and its hash value
class NodeTree:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.parent = None
        self.value = value
        self.hashValue = hashlib.sha256(value.encode('utf-8')).hexdigest()
# get leaves of the tree, index of the leaf,the root of the tree and calculate the path of the proof
def proofOfInclusion(leaves_of_tree,index,root):
    path_for_proof=[]
    node=leaves_of_tree[index]
    # while we don't arrive to root climb to parent and append the brother for proof
    while node.value!=root.value:
        # if there is a left child we append the right child with 1 leading in its hash value, otherwise append the left child with 0 leading in its hash value
        if(node.parent.left.value==node.value):
            node.parent.right.hashValue=str(1)+node.parent.right.hashValue
            path_for_proof.append(node.parent.right)
            node=node.parent
        else:
            node.parent.left.hashValue=str(0)+node.parent.left.hashValue
            path_for_proof.append(node.parent.left)
            node=node.parent
    return path_for_proof

# function that gets list of values and builds the merkle tree and return its root and leaves
def calcRoot(leaves):
    # if there is zero leaves
    if len(leaves)==0:
        return -1, -1
    nodes = []
    for i in leaves:
        nodes.append(NodeTree(i))
    leaves_of_tree=[]
    # if there is one leaves
    if len(leaves)==1:
        leaves_of_tree.append(nodes[0])
    # construct merkle tree by passing on the tree levels and calculate the nodes in each level
    while len(nodes) != 1:
        temporary = []
        #  calculate the nodes in the level
        for i in range(0, len(nodes), 2):
            node1 = nodes[i]
            if i + 1 < len(nodes):
                node2 = nodes[i + 1]
            else:
                # adding to leaves_of_tree list the single node in bottom level
                if (len(nodes) == len(leaves)):
                    leaves_of_tree.append(nodes[i])
                temporary.append(nodes[i])
                break
            # calculate the value of parent
            hashConcat = node1.hashValue + node2.hashValue
            parent = NodeTree(hashConcat)
            parent.left = node1
            parent.right = node2
            node1.parent=parent
            node2.parent=parent
            # adding the leaves to leaves_of_tree list (the nodes in first level from the end)
            if(len(nodes)==len(leaves)):
                leaves_of_tree.append(node1)
                leaves_of_tree.append(node2)
            temporary.append(parent)
        nodes = temporary

    return nodes[0], leaves_of_tree

if __name__ == '__main__':
    leaves = []
    # get input from user and perform action accordingly
    while 1:
        try:
            opt = input()
            if opt[0] == "1" and opt[1]==" ":
                try:
                    # adding the value that user gave to leaves list
                    num, additional=opt.split()
                    leaves.append(additional)
                except:
                    print("\n")
                    continue
            elif opt[0] == "2" and (len(opt) == 1):
                # calculate the root of merkle tree according to the leaves list
                root, leaves_of_tree = calcRoot(leaves)
                if root!=-1:
                    print(root.hashValue)
            elif opt[0] == "3" and opt[1]==" ":
                try:
                    num, additional=opt.split()
                    # calculate the root
                    root, leaves_of_tree = calcRoot(leaves)
                    path_for_proof=proofOfInclusion(leaves_of_tree,int(additional),root)
                    list_hashes=[]
                    # arrange in list the hash values of the nodes we calculated and print them with the root
                    for node in path_for_proof:
                        list_hashes.append(node.hashValue)
                    print(root.hashValue, ' '.join(list_hashes))
                except:
                    print("\n")
                    continue

            elif opt[0] == "4" and opt[1]==" ":
                try:
                    # Insert the parameters we get from user into variables
                    inp = opt.split(" ")
                    leafHash=inp[1]
                    root_input=inp[2]
                    path_input=inp[3:len(opt)]
                    hashRealPath=[]
                    root, leaves_of_tree = calcRoot(leaves)
                    # calculate the real proof path of the leaf we get from user
                    for i in range(len(leaves_of_tree)):
                        if leaves_of_tree[i].hashValue==leafHash or leaves_of_tree[i].value==leafHash:
                            realPath=proofOfInclusion(leaves_of_tree, i, root)
                            for node in realPath:
                                hashRealPath.append(node.hashValue)
                            break
                    # print True if the proof we get from user compatible with the real proof,otherwise print False
                    if(root_input==root.hashValue) and (path_input==hashRealPath):
                        print("True")
                    else:
                        print("False")
                except:
                    print("\n")
                    continue
            elif opt[0] == "5" and (len(opt)==1):
                # generate secret key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                # save the secret key in file
                alg = serialization.NoEncryption()
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=alg
                )
                with open("sk.pem", "wb") as f:
                    f.write(pem)
                # print the secret key
                print(pem.decode("utf-8"))

                # generate public key
                public_key = private_key.public_key()
                # save the public key in file
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                with open("pk.pem", "wb") as f:
                    f.write(pem)
                # print the public key
                print(pem.decode("utf-8"))

            elif (opt.split()[0]=="6" and (len(opt.split()[0])==1)) and (opt.split()[1]=="-----BEGIN") and opt.split()[2]=="RSA" and opt.split()[3]=="PRIVATE" and opt.split()[4]=="KEY-----":
                try:
                    # get from user the private key line by line
                    x=input()
                    array=[]
                    array.append("-----BEGIN RSA PRIVATE KEY-----")
                    while x!="-----END RSA PRIVATE KEY-----":
                        array.append(x)
                        x=input()
                    array.append(x+'\n')
                    privateKeyInput='\n'.join(array)
                    # calculate the root message and convert the private key we get to key form
                    root, leaves_of_tree = calcRoot(leaves)
                    root_message=root.hashValue
                    private_key_input=serialization.load_pem_private_key(privateKeyInput.encode('utf-8'), password=None, backend=default_backend())
                    # sign on the root message and print it
                    signature = base64.b64encode(private_key_input.sign(
                        root_message.encode('utf-8'),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    ))
                    print(signature.decode())
                except:
                    print("\n")
                    continue

            elif (opt.split()[0]=="7" and (len(opt.split()[0])==1)) and (opt.split()[1]=="-----BEGIN") and opt.split()[2]=="PUBLIC" and opt.split()[3]=="KEY-----":
                try:
                    # get from user the public key line by line
                    x=input()
                    array=[]
                    array.append("-----BEGIN PUBLIC KEY-----")
                    while x!="-----END PUBLIC KEY-----":
                        array.append(x)
                        x=input()
                    array.append(x+'\n')
                    publicKeyInput='\n'.join(array)
                    # Insert additional parameters (signature and message) we get from user into variables
                    signatureAndMessage=input()
                    while signatureAndMessage=='':
                        signatureAndMessage=input()
                    signature_input, message_input=signatureAndMessage.split()
                    try:
                        # convert the public key we get to key form
                        public_key_input=serialization.load_pem_public_key(publicKeyInput.encode('utf-8'), backend=default_backend())
                        # verify the signature
                        public_key_input.verify(
                            base64.b64decode(signature_input.encode('utf-8')),
                            message_input.encode('utf-8'),
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        # print "True" if it is verified,otherwise print "False"
                        print("True")
                    except:
                        print("False")
                except:
                    print("\n")
                    continue
            else:
                print("\n")
                continue
        except:
            print("\n")
            continue


